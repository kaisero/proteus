package resolve

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/okaiser/proteus/internal/appid"
	"github.com/okaiser/proteus/internal/config"
)

// Application is a custom application of the configuration, visible in a
// scope.
type Application struct {
	Object
	// App is the application as a filter and application-default read it:
	// Custom is set, and the name keeps its configured case (spec 2026-10-16
	// P14). It holds no ImplicitUse: as observed on fw02, PAN-OS 12.2.3, a
	// custom application refuses implicit-use-applications (spec 2026-10-16 I9).
	App appid.App
	// Err is a value of the entry that cannot be read: the risk or the default
	// block. The device checks both at commit, so only a hand-written file has
	// one. App then holds what could be read, and its Default allows every
	// protocol and port.
	Err error
}

// ApplicationFilter is an application filter of the configuration, visible in
// a scope.
type ApplicationFilter struct {
	Object
	Filter appid.Filter
}

// Applications returns the custom applications visible in a scope, a vsys
// application hiding a shared one of its name.
func Applications(cfg *config.Config, sc config.Scope) []Application {
	elems := elementsInChain(cfg, chainFor(sc), "application", nil)
	out := make([]Application, 0, len(elems))
	for _, o := range elems {
		app, err := customApp(o.Name, o.elem)
		out = append(out, Application{Object: o.Object, App: app, Err: err})
	}
	return out
}

// customApp reads a custom application entry. Its default ports come from its
// own default block (spec 2026-10-16 P7); without one it allows every protocol
// and port (P6). A child that holds yes or no is a flag, by its configuration
// name, which is the content name too (S10).
func customApp(name string, e *config.Element) (appid.App, error) {
	a := appid.App{Name: name, Custom: true, Flags: map[string]bool{}, Default: appid.Default{None: true}}
	var errs []error
	for _, c := range e.Children {
		switch c.Name {
		case "category":
			a.Category = c.Text
		case "subcategory":
			a.Subcategory = c.Text
		case "technology":
			a.Technology = c.Text
		case "description":
			a.Description = c.Text
		case "parent-app":
			a.Parent = c.Text
		case "risk":
			r, err := strconv.Atoi(c.Text)
			if err != nil {
				errs = append(errs, fmt.Errorf("risk %q: %w", c.Text, err))
			}
			a.Risk = r
		case "default":
			def, err := appid.CustomDefault(c.Child("port").Members(), c.Child("ident-by-ip-protocol").TextOr(""),
				c.Child("ident-by-icmp-type") != nil, c.Child("ident-by-icmp6-type") != nil)
			if err != nil {
				errs = append(errs, fmt.Errorf("default: %w", err))
				def = appid.Default{None: true}
			}
			a.Default = def
		default:
			if c.Text == "yes" || c.Text == "no" {
				a.Flags[c.Name] = c.Text == "yes"
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return a, fmt.Errorf("application %s: %w", name, err)
	}
	return a, nil
}

// ApplicationFilters returns the application filters visible in a scope, a
// vsys filter hiding a shared one of its name.
func ApplicationFilters(cfg *config.Config, sc config.Scope) []ApplicationFilter {
	elems := elementsInChain(cfg, chainFor(sc), "application-filter", nil)
	out := make([]ApplicationFilter, 0, len(elems))
	for _, o := range elems {
		f := appid.Filter{Name: o.Name, Criteria: map[string][]string{}}
		readCriteria(o.elem, &f)
		out = append(out, ApplicationFilter{Object: o.Object, Filter: f})
	}
	return out
}

// readCriteria reads the fields of a filter entry by their element names.
// appid decides what each name selects (appid.FilterField), so a field this
// package does not know still reaches the filter. An element that holds
// other elements and no member, such as tagging, is no field: its children
// are, so the tags land under tag.
func readCriteria(e *config.Element, f *appid.Filter) {
	for _, c := range e.Children {
		switch {
		case c.Name == "exclude":
			f.Exclude = append(f.Exclude, c.Members()...)
		case c.Name == "no-tag":
			// tagging no-tag yes adds no restriction, as measured on the lab
			// VM, PAN-OS 12.1.9 (spec 2026-10-16 S14).
		case len(c.Children) == 0:
			f.Criteria[c.Name] = append(f.Criteria[c.Name], c.Text)
		case c.Child("member") != nil:
			f.Criteria[c.Name] = append(f.Criteria[c.Name], c.Members()...)
		default:
			readCriteria(c, f)
		}
	}
}

// ApplicationTags returns, by application name, the tags that the
// application-tag entries of a scope add (spec 2026-10-16 S12). The names are
// as configured: the configuration matches names exactly (P14). An empty entry
// maps to no tag. A vsys entry hides a shared entry of its name, with the
// shadowing of every other object (objectsInChain); no lab fact covers a
// shared and a vsys entry for one application.
func ApplicationTags(cfg *config.Config, sc config.Scope) map[string][]string {
	out := map[string][]string{}
	for _, o := range objectsInChain(cfg, chainFor(sc), "application-tag", nil) {
		out[o.Name] = o.Tags
	}
	return out
}
