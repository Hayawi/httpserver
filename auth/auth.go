package auth

import (
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"
)

var sessionManager *scs.SessionManager

func GetSessionManager() *scs.SessionManager {
	if sessionManager == nil {
		sessionManager = scs.New()
		sessionManager.Lifetime = 24 * time.Hour
		sessionManager.Cookie.Secure = true
	}
	return sessionManager
}

// Middleware to enforce authentication
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := GetSessionManager().GetString(r.Context(), "email")
		// Check if the user is authenticated
		if userID == "" {
			// Redirect to login if not authenticated
			//http.Redirect(w, r, "/auth/login", http.StatusFound)
			http.Error(w, "need re-authentication", http.StatusUnauthorized)
			return
		}

		// Proceed to the next handler
		next.ServeHTTP(w, r)
	})
}
