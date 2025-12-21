package model

// Service represents a backend service that can be accessed through the portal
type Service struct {
	Name         string            `json:"name"`
	DisplayName  string            `json:"display_name"`
	Description  string            `json:"description"`
	Icon         string            `json:"icon"`
	Location     string            `json:"location"`
	Upstream     string            `json:"upstream"`
	AuthRequired bool              `json:"auth_required"`
	Rewrite      string            `json:"rewrite"`
	Headers      ServiceHeaders    `json:"headers"`
	NginxExtra   string            `json:"nginx_extra"`
}

// ServiceHeaders represents header manipulation for a service
type ServiceHeaders struct {
	Add    map[string]string `json:"add"`
	Remove []string          `json:"remove"`
}

// ServiceList represents a list of services for the portal
type ServiceList struct {
	Services []Service `json:"services"`
	Total    int       `json:"total"`
}

// NewServiceList creates a service list from services
func NewServiceList(services []Service) *ServiceList {
	return &ServiceList{
		Services: services,
		Total:    len(services),
	}
}

// FilterByAuth filters services by authentication requirement
func (sl *ServiceList) FilterByAuth(requiresAuth bool) *ServiceList {
	var filtered []Service
	for _, svc := range sl.Services {
		if svc.AuthRequired == requiresAuth {
			filtered = append(filtered, svc)
		}
	}
	return NewServiceList(filtered)
}

// FindByName finds a service by name
func (sl *ServiceList) FindByName(name string) *Service {
	for i := range sl.Services {
		if sl.Services[i].Name == name {
			return &sl.Services[i]
		}
	}
	return nil
}

// FindByLocation finds a service by location path
func (sl *ServiceList) FindByLocation(location string) *Service {
	for i := range sl.Services {
		if sl.Services[i].Location == location {
			return &sl.Services[i]
		}
	}
	return nil
}
