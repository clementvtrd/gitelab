package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/clementvtrd/gitelab/internal/auth"
	"github.com/clementvtrd/gitelab/internal/config"
	"github.com/clementvtrd/gitelab/internal/httpd"
	"github.com/clementvtrd/gitelab/internal/sshd"
	"github.com/clementvtrd/gitelab/internal/store"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	db, err := store.Open(cfg.DBPath())
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if n, err := db.CountUsers(); err == nil && n == 0 && cfg.AdminUser != "" {
		hash, err := auth.HashPassword(cfg.AdminPass)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := db.CreateUser(cfg.AdminUser, cfg.AdminUser+"@localhost", hash, true); err != nil {
			log.Fatal(err)
		}
		log.Printf("bootstrapped admin user %q", cfg.AdminUser)
	}

	sshSrv, err := sshd.New(cfg, db)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		if err := sshSrv.ListenAndServe(); err != nil {
			log.Printf("ssh server stopped: %v", err)
		}
	}()

	hs, err := httpd.New(cfg, db)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Addr: cfg.HTTPAddr, Handler: hs.Handler(), ReadHeaderTimeout: 10 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("gitelab up: http=%s ssh=%s data=%s external=%s", cfg.HTTPAddr, cfg.SSHAddr, cfg.DataDir, cfg.ExternalURL)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
