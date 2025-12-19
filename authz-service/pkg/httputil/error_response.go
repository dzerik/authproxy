package httputil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"text/template"
	"time"

	"github.com/your-org/authz-service/internal/config"
)

// ErrorData holds data for error response templates.
type ErrorData struct {
	StatusCode int       `json:"status_code"`
	Status     string    `json:"status"`
	Message    string    `json:"message"`
	Reason     string    `json:"reason,omitempty"`
	RequestID  string    `json:"request_id,omitempty"`
	Path       string    `json:"path,omitempty"`
	Method     string    `json:"method,omitempty"`
	Timestamp  time.Time `json:"timestamp,omitempty"`
}

// ErrorResponseWriter writes error responses in configured format.
type ErrorResponseWriter struct {
	cfg       config.ErrorResponseConfig
	templates map[string]*template.Template
}

// NewErrorResponseWriter creates a new error response writer.
func NewErrorResponseWriter(cfg config.ErrorResponseConfig) *ErrorResponseWriter {
	w := &ErrorResponseWriter{
		cfg:       cfg,
		templates: make(map[string]*template.Template),
	}

	// Pre-compile custom templates
	if cfg.Format == config.ErrorFormatCustom {
		for key, tmpl := range cfg.CustomTemplates {
			if t, err := template.New(key).Parse(tmpl); err == nil {
				w.templates[key] = t
			}
		}
		if cfg.DefaultTemplate != "" {
			if t, err := template.New("default").Parse(cfg.DefaultTemplate); err == nil {
				w.templates["default"] = t
			}
		}
	}

	return w
}

// WriteError writes an error response to the http.ResponseWriter.
func (w *ErrorResponseWriter) WriteError(rw http.ResponseWriter, r *http.Request, statusCode int, message, reason string) {
	data := w.buildErrorData(r, statusCode, message, reason)

	// Set custom headers
	for key, value := range w.cfg.Headers {
		rw.Header().Set(key, value)
	}

	switch w.cfg.Format {
	case config.ErrorFormatJSON:
		w.writeJSON(rw, data)
	case config.ErrorFormatText:
		w.writeText(rw, data)
	case config.ErrorFormatHTML:
		w.writeHTML(rw, data)
	case config.ErrorFormatRFC7807:
		w.writeRFC7807(rw, data)
	case config.ErrorFormatEnvoy:
		w.writeEnvoy(rw, data)
	case config.ErrorFormatCustom:
		w.writeCustom(rw, data)
	default:
		w.writeJSON(rw, data)
	}
}

func (w *ErrorResponseWriter) buildErrorData(r *http.Request, statusCode int, message, reason string) ErrorData {
	data := ErrorData{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Message:    message,
	}

	if w.cfg.IncludeReason {
		data.Reason = reason
	}
	if w.cfg.IncludeRequestID {
		data.RequestID = getRequestID(r)
	}
	if w.cfg.IncludePath {
		data.Path = r.URL.Path
		data.Method = r.Method
	}
	if w.cfg.IncludeTimestamp {
		data.Timestamp = time.Now().UTC()
	}

	return data
}

func (w *ErrorResponseWriter) writeJSON(rw http.ResponseWriter, data ErrorData) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(data.StatusCode)

	response := map[string]interface{}{
		"error":   toSnakeCase(data.Status),
		"status":  data.StatusCode,
		"message": data.Message,
	}
	if data.Reason != "" {
		response["reason"] = data.Reason
	}
	if data.RequestID != "" {
		response["request_id"] = data.RequestID
	}
	if data.Path != "" {
		response["path"] = data.Path
		response["method"] = data.Method
	}
	if !data.Timestamp.IsZero() {
		response["timestamp"] = data.Timestamp.Format(time.RFC3339)
	}

	json.NewEncoder(rw).Encode(response)
}

func (w *ErrorResponseWriter) writeText(rw http.ResponseWriter, data ErrorData) {
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rw.WriteHeader(data.StatusCode)

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%d %s: %s", data.StatusCode, data.Status, data.Message)
	if data.Reason != "" {
		fmt.Fprintf(&buf, " (%s)", data.Reason)
	}
	if data.RequestID != "" {
		fmt.Fprintf(&buf, " [request_id=%s]", data.RequestID)
	}
	buf.WriteTo(rw)
}

func (w *ErrorResponseWriter) writeHTML(rw http.ResponseWriter, data ErrorData) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(data.StatusCode)

	fmt.Fprintf(rw, `<!DOCTYPE html>
<html>
<head>
    <title>%d %s</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; margin-top: 0; }
        .status { color: #666; font-size: 1.2em; }
        .message { margin: 20px 0; color: #444; }
        .details { font-size: 0.9em; color: #888; margin-top: 20px; border-top: 1px solid #eee; padding-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>%d %s</h1>
        <div class="message">%s</div>`,
		data.StatusCode, html.EscapeString(data.Status),
		data.StatusCode, html.EscapeString(data.Status),
		html.EscapeString(data.Message))

	if data.Reason != "" || data.RequestID != "" {
		fmt.Fprintf(rw, `<div class="details">`)
		if data.Reason != "" {
			fmt.Fprintf(rw, `<p><strong>Reason:</strong> %s</p>`, html.EscapeString(data.Reason))
		}
		if data.RequestID != "" {
			fmt.Fprintf(rw, `<p><strong>Request ID:</strong> %s</p>`, html.EscapeString(data.RequestID))
		}
		fmt.Fprintf(rw, `</div>`)
	}

	fmt.Fprintf(rw, `
    </div>
</body>
</html>`)
}

func (w *ErrorResponseWriter) writeRFC7807(rw http.ResponseWriter, data ErrorData) {
	rw.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	rw.WriteHeader(data.StatusCode)

	response := map[string]interface{}{
		"type":   "about:blank",
		"title":  data.Status,
		"status": data.StatusCode,
		"detail": data.Message,
	}
	if data.Reason != "" {
		response["reason"] = data.Reason
	}
	if data.RequestID != "" {
		response["instance"] = fmt.Sprintf("urn:request:%s", data.RequestID)
	}
	if data.Path != "" {
		response["path"] = data.Path
	}

	json.NewEncoder(rw).Encode(response)
}

func (w *ErrorResponseWriter) writeEnvoy(rw http.ResponseWriter, data ErrorData) {
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rw.WriteHeader(data.StatusCode)

	// Envoy RBAC style response
	switch data.StatusCode {
	case http.StatusUnauthorized:
		fmt.Fprint(rw, "UNAUTHENTICATED")
	case http.StatusForbidden:
		fmt.Fprint(rw, "RBAC: access denied")
	default:
		fmt.Fprintf(rw, "%s", data.Message)
	}
}

func (w *ErrorResponseWriter) writeCustom(rw http.ResponseWriter, data ErrorData) {
	// Set content type
	contentType := w.cfg.ContentType
	if contentType == "" {
		contentType = "application/json; charset=utf-8"
	}
	rw.Header().Set("Content-Type", contentType)
	rw.WriteHeader(data.StatusCode)

	// Find template for status code
	statusKey := strconv.Itoa(data.StatusCode)
	tmpl := w.templates[statusKey]
	if tmpl == nil {
		tmpl = w.templates["default"]
	}

	if tmpl != nil {
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, data); err == nil {
			buf.WriteTo(rw)
			return
		}
	}

	// Fallback to JSON if template execution fails
	json.NewEncoder(rw).Encode(data)
}

// getRequestID extracts request ID from headers or context.
func getRequestID(r *http.Request) string {
	if id := r.Header.Get("X-Request-ID"); id != "" {
		return id
	}
	if id := r.Header.Get("X-Correlation-ID"); id != "" {
		return id
	}
	return ""
}

// toSnakeCase converts "Bad Request" to "bad_request".
func toSnakeCase(s string) string {
	var result bytes.Buffer
	for i, c := range s {
		if c == ' ' {
			result.WriteByte('_')
		} else if c >= 'A' && c <= 'Z' {
			if i > 0 {
				result.WriteByte('_')
			}
			result.WriteByte(byte(c) + 32)
		} else {
			result.WriteRune(c)
		}
	}
	return result.String()
}

// DefaultErrorResponseWriter returns a writer with default JSON configuration.
func DefaultErrorResponseWriter() *ErrorResponseWriter {
	return NewErrorResponseWriter(config.ErrorResponseConfig{
		Format:           config.ErrorFormatJSON,
		IncludeRequestID: true,
		IncludeReason:    true,
	})
}
