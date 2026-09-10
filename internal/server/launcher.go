package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	corelauncher "github.com/gantry-tools/gantry-core/launcher"
)

func (s *Server) launcherRoot(static http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Has("config") {
			s.serveLauncher(static, w, r)
			return
		}
		instances, err := s.loadLauncherInstances(r)
		if err != nil {
			http.Error(w, "launcher unavailable", 500)
			return
		}
		switch len(instances) {
		case 0:
			http.Redirect(w, r, "/app/", 302)
		case 1:
			target, err := corelauncher.AppURL(instances[0])
			if err != nil {
				http.Error(w, "invalid launcher configuration", 500)
				return
			}
			http.Redirect(w, r, target, 302)
		default:
			s.serveLauncher(static, w, r)
		}
	})
}

func rbacLauncherManage(role string) bool { return role == "owner" || role == "admin" }

func (s *Server) serveLauncher(static http.Handler, w http.ResponseWriter, r *http.Request) {
	clone := r.Clone(r.Context())
	clone.URL.Path, clone.URL.RawPath = "/launcher.html", ""
	w.Header().Set("Cache-Control", "no-store")
	static.ServeHTTP(w, clone)
}

func (s *Server) loadLauncherInstances(r *http.Request) ([]corelauncher.Instance, error) {
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT id,name,domain,port FROM launcher_instances ORDER BY position,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []corelauncher.Instance{}
	for rows.Next() {
		var item corelauncher.Instance
		if err := rows.Scan(&item.ID, &item.Name, &item.Domain, &item.Port); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Server) handleLauncherInstances(w http.ResponseWriter, r *http.Request, _ principal) {
	instances, err := s.loadLauncherInstances(r)
	if err != nil {
		writeError(w, 500, "launcher unavailable")
		return
	}
	view, err := corelauncher.MakeView("webfleet", instances)
	if err != nil {
		writeError(w, 500, "invalid launcher configuration")
		return
	}
	writeJSON(w, 200, view)
}

func (s *Server) handleLauncherConfig(w http.ResponseWriter, r *http.Request, p principal) {
	if !rbacLauncherManage(p.Role) {
		writeError(w, 403, "launcher.configure.all required")
		return
	}
	var document corelauncher.Document
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		writeError(w, 400, "invalid json")
		return
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		writeError(w, 400, "invalid json")
		return
	}
	instances, err := corelauncher.Normalize("webfleet", document)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, 500, "unable to save launcher configuration")
		return
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(r.Context(), `DELETE FROM launcher_instances`); err == nil {
		for position, item := range instances {
			_, err = tx.ExecContext(r.Context(), `INSERT INTO launcher_instances(id,position,name,domain,port) VALUES(?,?,?,?,?)`, item.ID, position, item.Name, item.Domain, item.Port)
			if err != nil {
				break
			}
		}
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		writeError(w, 500, "unable to save launcher configuration")
		return
	}
	view, _ := corelauncher.MakeView("webfleet", instances)
	writeJSON(w, 200, view)
}
