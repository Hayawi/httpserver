package routes

import (
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/cors"
	"github.com/spf13/viper"
)

const (
	GETMethod     = iota
	POSTMethod    = iota
	OPTIONSMethod = iota
	PUTMethod     = iota
	DELETEMethod  = iota
)

type route struct {
	path         string
	method       int
	handler      http.HandlerFunc
	isAuthMethod bool
}

var (
	apiRouteList  []route
	authRouteList []route
)

// AddRoute registers a new route to the application.
//
// Parameters:
// - path: The URL path for the route.
// - method: The HTTP method for the route (e.g., GETMethod, POSTMethod).
// - handler: The function to handle requests to this route.
// - isAuthMethod: Whether the route requires authentication.
func AddRoute(path string, method int, handler http.HandlerFunc, isAuthMethod bool) {
	if isAuthMethod {
		apiRouteList = append(apiRouteList, route{
			path:         path,
			method:       method,
			handler:      handler,
			isAuthMethod: isAuthMethod,
		})
	} else {
		authRouteList = append(authRouteList, route{
			path:         path,
			method:       method,
			handler:      handler,
			isAuthMethod: isAuthMethod,
		})
	}
}

// Setup configures the router with middleware, CORS, and routes.
//
// Parameters:
// - router: The chi.Mux router to configure.
// - allowedOrigins: A list of allowed origins for CORS.
// - authMiddleWare: Middleware for authentication, applied if FORCE_AUTH is enabled.
func Setup(router *chi.Mux, allowedOrigins []string, authMiddleWare func(http.Handler) http.Handler, allowCredentials bool) {
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(middleware.Timeout(60 * time.Second))
	router.Use(cors.New(cors.Options{
		AllowedOrigins:   allowedOrigins,                                      // Frontend origin
		AllowCredentials: allowCredentials,                                    // Allow cookies (important)
		AllowedMethods:   []string{"GET", "POST", "OPTIONS", "PUT", "DELETE"}, // Allowed HTTP methods
		AllowedHeaders:   []string{"Content-Type", "Authorization"},           // Allowed headers
	}).Handler)

	router.Route("/api", func(router chi.Router) {
		if viper.GetBool("FORCE_AUTH") && authMiddleWare != nil {
			router.Use(authMiddleWare)
		}

		for _, r := range apiRouteList {
			switch r.method {
			case GETMethod:
				router.Get(r.path, r.handler)
			case POSTMethod:
				router.Post(r.path, r.handler)
			case OPTIONSMethod:
				router.Options(r.path, r.handler)
			case PUTMethod:
				router.Put(r.path, r.handler)
			case DELETEMethod:
				router.Put(r.path, r.handler)
			default:
				log.Fatalf("method type for path %s not supported", r.path)
			}
		}
	})

	for _, r := range authRouteList {
		switch r.method {
		case GETMethod:
			router.Get(r.path, r.handler)
		case POSTMethod:
			router.Post(r.path, r.handler)
		case OPTIONSMethod:
			router.Options(r.path, r.handler)
		case PUTMethod:
			router.Put(r.path, r.handler)
		case DELETEMethod:
			router.Put(r.path, r.handler)
		default:
			log.Fatalf("method type for path %s not supported", r.path)
		}
	}
}
