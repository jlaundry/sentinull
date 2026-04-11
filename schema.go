package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// reservedColumns are columns that exist in schemas but cannot be written to by clients.
var reservedColumns = map[string]bool{
	"_ResourceId":     true,
	"id":              true,
	"_SubscriptionId": true,
	"TenantId":        true,
	"Type":            true,
	"UniqueId":        true,
	"Title":           true,
}

// columnNameRe validates that a column name starts with a letter and contains
// only up to 45 alphanumeric characters and underscores.
var columnNameRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,44}$`)

// Note: leading underscore columns like _ResourceId are schema-internal reserved
// names that also appear in records; the regex is applied only to non-reserved
// user-submitted column names.

// ColumnType represents the data type of a column in a table schema.
type ColumnType int

const (
	TypeString   ColumnType = iota // string
	TypeInt                        // int (JSON number coercible to integer)
	TypeReal                       // real (JSON number)
	TypeDatetime                   // datetime (ISO 8601 / common datetime strings)
	TypeBool                       // bool
)

// Column defines a single column in a table schema.
type Column struct {
	Name string
	Type ColumnType
}

// Schema defines the columns that a stream accepts.
// All columns are optional, but any column present in a record must:
//  1. Exist in the schema.
//  2. Have a value coercible to the declared type.
type Schema struct {
	Columns []Column
}

// columnMap returns the columns indexed by name for fast lookup.
func (s Schema) columnMap() map[string]ColumnType {
	m := make(map[string]ColumnType, len(s.Columns))
	for _, c := range s.Columns {
		m[c.Name] = c.Type
	}
	return m
}

// ValidateRecord checks a single JSON record (unmarshalled into map[string]any)
// against this schema. It returns an error for:
//   - Reserved columns that cannot be written to.
//   - Column names not present in the schema.
//   - Values that cannot be coerced to the declared column type.
func (s Schema) ValidateRecord(record map[string]any) error {
	cols := s.columnMap()
	for key, val := range record {
		if reservedColumns[key] {
			return fmt.Errorf("column %q is reserved and cannot be written to", key)
		}
		colType, ok := cols[key]
		if !ok {
			return fmt.Errorf("unknown column %q", key)
		}
		if val == nil {
			continue // null is acceptable for any optional column
		}
		if err := checkType(key, val, colType); err != nil {
			return err
		}
	}
	return nil
}

// checkType validates that val can be coerced to the expected ColumnType.
func checkType(name string, val any, ct ColumnType) error {
	switch ct {
	case TypeString:
		if _, ok := val.(string); !ok {
			return fmt.Errorf("column %q: expected string, got %T", name, val)
		}
	case TypeInt:
		switch v := val.(type) {
		case float64:
			if v != float64(int64(v)) {
				return fmt.Errorf("column %q: expected int, got float", name)
			}
		case string:
			if _, err := strconv.ParseInt(v, 10, 64); err != nil {
				return fmt.Errorf("column %q: expected int, got non-numeric string", name)
			}
		default:
			return fmt.Errorf("column %q: expected int, got %T", name, val)
		}
	case TypeReal:
		switch v := val.(type) {
		case float64:
			// ok
		case string:
			if _, err := strconv.ParseFloat(v, 64); err != nil {
				return fmt.Errorf("column %q: expected real, got non-numeric string", name)
			}
		default:
			_ = v
			return fmt.Errorf("column %q: expected real, got %T", name, val)
		}
	case TypeDatetime:
		switch v := val.(type) {
		case string:
			if !parseDatetime(v) {
				return fmt.Errorf("column %q: expected datetime, got unparseable string %q", name, v)
			}
		default:
			return fmt.Errorf("column %q: expected datetime, got %T", name, val)
		}
	case TypeBool:
		switch v := val.(type) {
		case bool:
			// ok
		case string:
			lower := strings.ToLower(v)
			if lower != "true" && lower != "false" {
				return fmt.Errorf("column %q: expected bool, got non-boolean string", name)
			}
		default:
			return fmt.Errorf("column %q: expected bool, got %T", name, val)
		}
	}
	return nil
}

// parseDatetime attempts common datetime formats.
func parseDatetime(s string) bool {
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02T15:04:05Z",
		"2006-01-02",
	}
	for _, f := range formats {
		if _, err := time.Parse(f, s); err == nil {
			return true
		}
	}
	return false
}

// streamSchemas maps stream names to their Schema.
// Custom-* streams are never validated and do not appear here.
var streamSchemas = map[string]Schema{}

// RegisterSchema registers a schema for a given stream name.
func RegisterSchema(stream string, s Schema) {
	streamSchemas[stream] = s
}

// LookupSchema returns the schema for a stream, or nil if none is registered
// (i.e. Custom-* streams or unknown Microsoft- streams without a schema).
func LookupSchema(stream string) *Schema {
	s, ok := streamSchemas[stream]
	if !ok {
		return nil
	}
	return &s
}

func init() {
	RegisterSchema("Microsoft-Syslog", Schema{
		Columns: []Column{
			{Name: "_BilledSize", Type: TypeReal},
			{Name: "CollectorHostName", Type: TypeString},
			{Name: "Computer", Type: TypeString},
			{Name: "EventTime", Type: TypeDatetime},
			{Name: "Facility", Type: TypeString},
			{Name: "HostIP", Type: TypeString},
			{Name: "HostName", Type: TypeString},
			{Name: "_IsBillable", Type: TypeString},
			{Name: "ProcessID", Type: TypeInt},
			{Name: "ProcessName", Type: TypeString},
			{Name: "_ResourceId", Type: TypeString},
			{Name: "SeverityLevel", Type: TypeString},
			{Name: "SourceSystem", Type: TypeString},
			{Name: "_SubscriptionId", Type: TypeString},
			{Name: "SyslogMessage", Type: TypeString},
			{Name: "TimeGenerated", Type: TypeDatetime},
			{Name: "Type", Type: TypeString},
		},
	})
}
