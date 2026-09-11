package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zeal/auth/internal/config"
	"github.com/zeal/auth/internal/db"
	"github.com/zeal/auth/internal/handler"
	"github.com/zeal/auth/internal/repository"
	"github.com/zeal/auth/internal/service"
)

func main() {
	cfg := config.Load()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	pool, err := db.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer pool.Close()

	if err := service.EnsureInitialKey(ctx, pool, cfg.JWTKID, cfg.KeyEncryptionKey); err != nil {
		log.Fatalf("ensure initial signing key: %v", err)
	}

	keySvc := service.NewKeyService(pool, cfg.KeyEncryptionKey)

	fositeCfg := handler.DefaultFositeConfig(
		"https://"+cfg.CookieDomain,
		cfg.CookieDomain,
	)
	fositeCfg.GlobalSecret = []byte(os.Getenv("FOSITE_GLOBAL_SECRET"))
	if len(fositeCfg.GlobalSecret) < 32 {
		fositeCfg.GlobalSecret = []byte("fosite-dev-secret-replace-in-prod-32bytes!!")
	}

	oauthHandler, err := handler.NewFositeServer(pool, keySvc, fositeCfg)
	if err != nil {
		log.Fatalf("fosite server: %v", err)
	}

	oauth2Handler := handler.NewOAuth2Handler(oauthHandler, pool, keySvc, fositeCfg)

	userRepo := repository.NewUserRepository(pool)
	verificationRepo := repository.NewVerificationRepository(pool)
	resetRepo := repository.NewResetRepository(pool)
	authSvc := service.NewAuthService(userRepo)
	emailSvc := service.NewEmailService(userRepo, verificationRepo, resetRepo, pool)

	router := handler.NewRouter(handler.RouterDeps{
		Pool:   pool,
		Auth:   authSvc,
		Email:  emailSvc,
		OAuth:  oauthHandler,
		OAuth2: oauth2Handler,
	})

	srv := &http.Server{
		Addr:         ":" + cfg.ServerPort,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("listening on :%s", cfg.ServerPort)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("shutdown: %v", err)
	}

	log.Println("stopped")
}
