package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/inconshreveable/log15"
	"github.com/knqyf263/gost/db"
	"github.com/knqyf263/gost/util"
	"github.com/labstack/echo"
	"github.com/labstack/echo/engine/standard"
	"github.com/labstack/echo/middleware"
	"github.com/spf13/viper"
)

// Start starts CVE dictionary HTTP Server.
func Start(logDir string, driver db.DB) error {
	e := echo.New()
	e.SetDebug(viper.GetBool("debug"))

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// setup access logger
	logPath := filepath.Join(logDir, "access.log")
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		if _, err := os.Create(logPath); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Output: f,
	}))

	// Routes
	e.Get("/health", health())
	e.Get("/redhat/cves/:id", getRedhatCve(driver))
	e.Get("/debian/cves/:id", getDebianCve(driver))

	e.Get("/redhat/:release/pkgs/:name/unfixed-cves", getUnfixedCves(driver))

	bindURL := fmt.Sprintf("%s:%s", viper.GetString("bind"), viper.GetString("port"))
	log15.Info("Listening", "URL", bindURL)

	e.Run(standard.New(bindURL))
	return nil
}

// Handler
func health() echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.String(http.StatusOK, "")
	}
}

// Handler
func getRedhatCve(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		cveid := c.Param("id")
		cveDetail := driver.GetRedhat(cveid)
		//TODO error
		return c.JSON(http.StatusOK, &cveDetail)
	}
}

// Handler
func getDebianCve(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		cveid := c.Param("id")
		cveDetail := driver.GetDebian(cveid)
		//TODO error
		return c.JSON(http.StatusOK, &cveDetail)
	}
}

// Handler
func getUnfixedCves(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		release := util.Major(c.Param("release"))
		pkgName := c.Param("name")
		cveDetail, err := driver.GetUnfixedCvesRedhat(release, pkgName)
		if err != nil {
			log15.Error("Failed to getUnfixedCves", err)
			return c.JSON(http.StatusInternalServerError, nil)
		}
		return c.JSON(http.StatusOK, &cveDetail)
	}
}
