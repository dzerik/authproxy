package policy

import (
	"container/list"
	"net/netip"
	"regexp"
	"strings"
	"sync"
)

const (
	// DefaultPathMatcherCacheSize is the default maximum number of cached patterns.
	DefaultPathMatcherCacheSize = 1000
	// DefaultCIDRMatcherCacheSize is the default maximum number of cached CIDRs.
	DefaultCIDRMatcherCacheSize = 500
)

// PathMatcher provides path matching with regex caching and entity extraction.
// Uses LRU eviction to prevent unbounded memory growth.
type PathMatcher struct {
	mu       sync.RWMutex
	cache    map[string]*patternCacheEntry
	order    *list.List // LRU order: front = most recently used
	capacity int
}

// patternCacheEntry holds a cached pattern with its LRU list element.
type patternCacheEntry struct {
	pattern  *compiledPattern
	key      string
	element  *list.Element
}

// compiledPattern holds a compiled regex with its named groups.
type compiledPattern struct {
	regex      *regexp.Regexp
	groupNames []string
	isTemplate bool
}

// MatchResult contains the result of a path match operation.
type MatchResult struct {
	// Matched indicates if the pattern matched the path.
	Matched bool
	// Params contains extracted named parameters from the path.
	Params map[string]string
	// Pattern is the pattern that matched (useful when matching against multiple).
	Pattern string
}

// ResourceInfo contains extracted resource information from a path.
type ResourceInfo struct {
	// Type is the resource type (extracted from {resource_type}, {resource}, or {type}).
	Type string `json:"type,omitempty"`
	// ID is the resource identifier (extracted from {resource_id} or {id}).
	ID string `json:"id,omitempty"`
	// Action is the action being performed (extracted from {action} or derived from method).
	Action string `json:"action,omitempty"`
	// Params contains all extracted named parameters.
	Params map[string]string `json:"params,omitempty"`
}

// NewPathMatcher creates a new PathMatcher with an empty cache and default capacity.
func NewPathMatcher() *PathMatcher {
	return NewPathMatcherWithCapacity(DefaultPathMatcherCacheSize)
}

// NewPathMatcherWithCapacity creates a new PathMatcher with specified cache capacity.
func NewPathMatcherWithCapacity(capacity int) *PathMatcher {
	if capacity <= 0 {
		capacity = DefaultPathMatcherCacheSize
	}
	return &PathMatcher{
		cache:    make(map[string]*patternCacheEntry),
		order:    list.New(),
		capacity: capacity,
	}
}

// Match checks if a path matches a pattern and extracts named parameters.
// Supports two pattern formats:
// 1. Template syntax: /api/v1/{resource_type}/{resource_id}
// 2. Regex syntax: ^/api/v1/(?P<resource>\w+)/(?P<id>[^/]+)$
func (m *PathMatcher) Match(pattern, path string) MatchResult {
	compiled := m.getOrCompile(pattern)
	if compiled == nil {
		return MatchResult{Matched: false}
	}

	matches := compiled.regex.FindStringSubmatch(path)
	if matches == nil {
		return MatchResult{Matched: false}
	}

	// Extract named groups
	params := make(map[string]string)
	for i, name := range compiled.groupNames {
		if i < len(matches) && name != "" {
			params[name] = matches[i]
		}
	}

	return MatchResult{
		Matched: true,
		Params:  params,
		Pattern: pattern,
	}
}

// MatchAny tries to match a path against multiple patterns.
// Returns the first successful match result.
func (m *PathMatcher) MatchAny(patterns []string, path string) MatchResult {
	for _, pattern := range patterns {
		result := m.Match(pattern, path)
		if result.Matched {
			return result
		}
	}
	return MatchResult{Matched: false}
}

// MatchWithGlobFallback tries template/regex match first, then falls back to glob.
// This maintains backward compatibility with existing glob patterns.
func (m *PathMatcher) MatchWithGlobFallback(patterns []string, path string) MatchResult {
	for _, pattern := range patterns {
		// Try as template or regex first
		result := m.Match(pattern, path)
		if result.Matched {
			return result
		}

		// Fallback to simple glob matching for non-template patterns
		if !isTemplateOrRegex(pattern) {
			if globMatch(pattern, path) {
				return MatchResult{
					Matched: true,
					Pattern: pattern,
					Params:  make(map[string]string),
				}
			}
		}
	}
	return MatchResult{Matched: false}
}

// ExtractResource creates a ResourceInfo from match parameters.
// It looks for conventional parameter names and maps them to resource fields.
func ExtractResource(params map[string]string) *ResourceInfo {
	if len(params) == 0 {
		return nil
	}

	resource := &ResourceInfo{
		Params: params,
	}

	// Extract resource type from various conventional names
	for _, key := range []string{"resource_type", "resource", "type", "entity", "collection"} {
		if v, ok := params[key]; ok && resource.Type == "" {
			resource.Type = v
		}
	}

	// Extract resource ID from various conventional names
	for _, key := range []string{"resource_id", "id", "uuid", "key"} {
		if v, ok := params[key]; ok && resource.ID == "" {
			resource.ID = v
		}
	}

	// Extract action
	if v, ok := params["action"]; ok {
		resource.Action = v
	}

	return resource
}

// getOrCompile retrieves a compiled pattern from cache or compiles and caches it.
// Uses LRU eviction when cache is full.
func (m *PathMatcher) getOrCompile(pattern string) *compiledPattern {
	// Try read lock first for cache hit
	m.mu.RLock()
	entry, ok := m.cache[pattern]
	m.mu.RUnlock()

	if ok {
		// Move to front (most recently used) - requires write lock
		m.mu.Lock()
		// Re-check entry still exists after acquiring write lock
		if entry, ok = m.cache[pattern]; ok {
			m.order.MoveToFront(entry.element)
		}
		m.mu.Unlock()
		if ok {
			return entry.pattern
		}
	}

	// Compile the pattern
	compiled := compilePattern(pattern)
	if compiled == nil {
		return nil
	}

	// Store in cache with write lock
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check in case another goroutine compiled it
	if existing, ok := m.cache[pattern]; ok {
		m.order.MoveToFront(existing.element)
		return existing.pattern
	}

	// Evict oldest if at capacity
	for m.order.Len() >= m.capacity {
		m.evictOldest()
	}

	// Add new entry
	entry = &patternCacheEntry{
		pattern: compiled,
		key:     pattern,
	}
	entry.element = m.order.PushFront(entry)
	m.cache[pattern] = entry

	return compiled
}

// evictOldest removes the least recently used entry from cache.
// Must be called with write lock held.
func (m *PathMatcher) evictOldest() {
	oldest := m.order.Back()
	if oldest == nil {
		return
	}
	entry := oldest.Value.(*patternCacheEntry)
	delete(m.cache, entry.key)
	m.order.Remove(oldest)
}

// compilePattern compiles a pattern string to a regex.
func compilePattern(pattern string) *compiledPattern {
	var regexStr string
	var isTemplate bool

	if isTemplatePattern(pattern) {
		// Convert template syntax to regex
		regexStr = templateToRegex(pattern)
		isTemplate = true
	} else if isRegexPattern(pattern) {
		// Use regex as-is
		regexStr = pattern
		isTemplate = false
	} else {
		// Convert glob to regex
		regexStr = globToRegex(pattern)
		isTemplate = false
	}

	regex, err := regexp.Compile(regexStr)
	if err != nil {
		return nil
	}

	return &compiledPattern{
		regex:      regex,
		groupNames: regex.SubexpNames(),
		isTemplate: isTemplate,
	}
}

// isTemplatePattern checks if a pattern uses template syntax {param}.
func isTemplatePattern(pattern string) bool {
	return strings.Contains(pattern, "{") && strings.Contains(pattern, "}")
}

// isRegexPattern checks if a pattern is a regex (starts with ^ or ends with $).
func isRegexPattern(pattern string) bool {
	return strings.HasPrefix(pattern, "^") || strings.HasSuffix(pattern, "$") ||
		strings.Contains(pattern, "(?P<")
}

// isTemplateOrRegex checks if a pattern is either a template or regex.
func isTemplateOrRegex(pattern string) bool {
	return isTemplatePattern(pattern) || isRegexPattern(pattern)
}

// templateToRegex converts a template pattern to a regex with named groups.
// Example: /api/v1/{resource_type}/{resource_id}
// Becomes: ^/api/v1/(?P<resource_type>[^/]+)/(?P<resource_id>[^/]+)$
func templateToRegex(template string) string {
	var result strings.Builder
	result.WriteString("^")

	i := 0
	for i < len(template) {
		if template[i] == '{' {
			// Find closing brace
			end := strings.Index(template[i:], "}")
			if end == -1 {
				// Invalid template, treat literally
				result.WriteByte(template[i])
				i++
				continue
			}

			// Extract parameter name and optional pattern
			param := template[i+1 : i+end]
			name := param
			pattern := "[^/]+"

			// Check for custom pattern: {name:pattern}
			if colonIdx := strings.Index(param, ":"); colonIdx != -1 {
				name = param[:colonIdx]
				pattern = param[colonIdx+1:]
			}

			// Write named group
			result.WriteString("(?P<")
			result.WriteString(name)
			result.WriteString(">")
			result.WriteString(pattern)
			result.WriteString(")")

			i += end + 1
		} else if template[i] == '*' {
			// Wildcard
			if i+1 < len(template) && template[i+1] == '*' {
				// ** matches everything including slashes
				result.WriteString(".*")
				i += 2
			} else {
				// * matches everything except slashes
				result.WriteString("[^/]*")
				i++
			}
		} else if isRegexMetaChar(template[i]) {
			// Escape regex metacharacters
			result.WriteByte('\\')
			result.WriteByte(template[i])
			i++
		} else {
			result.WriteByte(template[i])
			i++
		}
	}

	result.WriteString("$")
	return result.String()
}

// globToRegex converts a glob pattern to a regex.
func globToRegex(glob string) string {
	var result strings.Builder
	result.WriteString("^")

	for i := 0; i < len(glob); i++ {
		switch glob[i] {
		case '*':
			if i+1 < len(glob) && glob[i+1] == '*' {
				result.WriteString(".*")
				i++
			} else {
				result.WriteString("[^/]*")
			}
		case '?':
			result.WriteString("[^/]")
		case '.', '+', '^', '$', '(', ')', '[', ']', '{', '}', '|', '\\':
			result.WriteByte('\\')
			result.WriteByte(glob[i])
		default:
			result.WriteByte(glob[i])
		}
	}

	result.WriteString("$")
	return result.String()
}

// isRegexMetaChar checks if a character is a regex metacharacter.
func isRegexMetaChar(c byte) bool {
	return c == '.' || c == '+' || c == '^' || c == '$' ||
		c == '(' || c == ')' || c == '[' || c == ']' ||
		c == '|' || c == '\\'
}

// globMatch performs simple glob matching using filepath.Match semantics.
func globMatch(pattern, path string) bool {
	// Simple glob implementation
	return matchGlob(pattern, path, 0, 0)
}

func matchGlob(pattern, str string, pi, si int) bool {
	for pi < len(pattern) {
		if si >= len(str) {
			// Check if remaining pattern is all stars
			for pi < len(pattern) {
				if pattern[pi] != '*' {
					return false
				}
				pi++
			}
			return true
		}

		switch pattern[pi] {
		case '*':
			if pi+1 < len(pattern) && pattern[pi+1] == '*' {
				// ** matches everything
				pi += 2
				if pi >= len(pattern) {
					return true
				}
				for i := si; i <= len(str); i++ {
					if matchGlob(pattern, str, pi, i) {
						return true
					}
				}
				return false
			}
			// * matches everything except /
			for i := si; i <= len(str); i++ {
				if i > si && str[i-1] == '/' {
					break
				}
				if matchGlob(pattern, str, pi+1, i) {
					return true
				}
			}
			return false
		case '?':
			if str[si] == '/' {
				return false
			}
			pi++
			si++
		default:
			if pattern[pi] != str[si] {
				return false
			}
			pi++
			si++
		}
	}

	return si >= len(str)
}

// CIDRMatcher provides CIDR matching with caching.
// Uses LRU eviction to prevent unbounded memory growth.
type CIDRMatcher struct {
	mu       sync.RWMutex
	cache    map[string]*cidrCacheEntry
	order    *list.List
	capacity int
}

// cidrCacheEntry holds a cached CIDR prefix with its LRU list element.
type cidrCacheEntry struct {
	prefix  netip.Prefix
	key     string
	element *list.Element
}

// NewCIDRMatcher creates a new CIDRMatcher with default capacity.
func NewCIDRMatcher() *CIDRMatcher {
	return NewCIDRMatcherWithCapacity(DefaultCIDRMatcherCacheSize)
}

// NewCIDRMatcherWithCapacity creates a new CIDRMatcher with specified cache capacity.
func NewCIDRMatcherWithCapacity(capacity int) *CIDRMatcher {
	if capacity <= 0 {
		capacity = DefaultCIDRMatcherCacheSize
	}
	return &CIDRMatcher{
		cache:    make(map[string]*cidrCacheEntry),
		order:    list.New(),
		capacity: capacity,
	}
}

// Match checks if an IP address matches any of the given CIDR patterns.
func (m *CIDRMatcher) Match(cidrs []string, ipStr string) bool {
	if len(cidrs) == 0 {
		return true // No restriction
	}

	// Parse the IP address
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		// Try to extract IP from address:port format
		if colonIdx := strings.LastIndex(ipStr, ":"); colonIdx != -1 {
			ip, err = netip.ParseAddr(ipStr[:colonIdx])
		}
		if err != nil {
			return false
		}
	}

	for _, cidr := range cidrs {
		// Handle wildcards
		if cidr == "*" {
			return true
		}

		// Get or parse prefix
		prefix := m.getOrParseCIDR(cidr)
		if !prefix.IsValid() {
			// Try exact match if not a valid CIDR
			if cidr == ipStr || cidr == ip.String() {
				return true
			}
			continue
		}

		if prefix.Contains(ip) {
			return true
		}
	}

	return false
}

// getOrParseCIDR retrieves a parsed prefix from cache or parses and caches it.
// Uses LRU eviction when cache is full.
func (m *CIDRMatcher) getOrParseCIDR(cidr string) netip.Prefix {
	// Try read lock first for cache hit
	m.mu.RLock()
	entry, ok := m.cache[cidr]
	m.mu.RUnlock()

	if ok {
		// Move to front (most recently used)
		m.mu.Lock()
		if entry, ok = m.cache[cidr]; ok {
			m.order.MoveToFront(entry.element)
		}
		m.mu.Unlock()
		if ok {
			return entry.prefix
		}
	}

	// Parse CIDR
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		// Try parsing as single IP
		ip, err := netip.ParseAddr(cidr)
		if err != nil {
			return netip.Prefix{}
		}
		// Convert single IP to /32 or /128 prefix
		bits := 32
		if ip.Is6() {
			bits = 128
		}
		prefix = netip.PrefixFrom(ip, bits)
	}

	// Cache the result with write lock
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check
	if existing, ok := m.cache[cidr]; ok {
		m.order.MoveToFront(existing.element)
		return existing.prefix
	}

	// Evict oldest if at capacity
	for m.order.Len() >= m.capacity {
		m.evictOldestCIDR()
	}

	// Add new entry
	entry = &cidrCacheEntry{
		prefix: prefix,
		key:    cidr,
	}
	entry.element = m.order.PushFront(entry)
	m.cache[cidr] = entry

	return prefix
}

// evictOldestCIDR removes the least recently used CIDR entry from cache.
// Must be called with write lock held.
func (m *CIDRMatcher) evictOldestCIDR() {
	oldest := m.order.Back()
	if oldest == nil {
		return
	}
	entry := oldest.Value.(*cidrCacheEntry)
	delete(m.cache, entry.key)
	m.order.Remove(oldest)
}

// ClearCache clears the pattern cache (useful for testing or hot reload).
func (m *PathMatcher) ClearCache() {
	m.mu.Lock()
	m.cache = make(map[string]*patternCacheEntry)
	m.order.Init()
	m.mu.Unlock()
}

// CacheSize returns the number of cached patterns.
func (m *PathMatcher) CacheSize() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.cache)
}

// CacheCapacity returns the maximum cache capacity.
func (m *PathMatcher) CacheCapacity() int {
	return m.capacity
}

// PrecompilePatterns pre-compiles a list of patterns to warm the cache.
// This is useful at startup to avoid cold-start latency on the first request.
func (m *PathMatcher) PrecompilePatterns(patterns []string) int {
	compiled := 0
	for _, pattern := range patterns {
		if pattern != "" && m.getOrCompile(pattern) != nil {
			compiled++
		}
	}
	return compiled
}

// CIDRCacheSize returns the number of cached CIDRs.
func (m *CIDRMatcher) CacheSize() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.cache)
}

// CIDRCacheCapacity returns the maximum cache capacity.
func (m *CIDRMatcher) CacheCapacity() int {
	return m.capacity
}

// ClearCache clears the CIDR cache.
func (m *CIDRMatcher) ClearCache() {
	m.mu.Lock()
	m.cache = make(map[string]*cidrCacheEntry)
	m.order.Init()
	m.mu.Unlock()
}
