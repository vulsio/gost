package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/inconshreveable/log15"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/spf13/viper"
	"github.com/vulsio/gost/db"
	"github.com/vulsio/gost/util"
	"golang.org/x/xerrors"
)

// Start starts CVE dictionary HTTP Server.
func Start(logToFile bool, logDir string, driver db.DB) error {
	e := echo.New()
	e.Debug = viper.GetBool("debug")

	// Middleware
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{Output: os.Stderr}))
	e.Use(middleware.Recover())

	// setup access logger
	if logToFile {
		logPath := filepath.Join(logDir, "access.log")
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return xerrors.Errorf("Failed to open a log file: %s", err)
		}
		defer f.Close()
		e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{Output: f}))
	}

	// Routes
	e.GET("/health", health())
	e.GET("/redhat/cves/:id", getRedhatCve(driver))
	e.GET("/debian/cves/:id", getDebianCve(driver))
	e.GET("/ubuntu/cves/:id", getUbuntuCve(driver))
	e.GET("/microsoft/cves/:id", getMicrosoftCve(driver))
	e.GET("/redhat/:release/pkgs/:name/unfixed-cves", getUnfixedCvesRedhat(driver))
	e.GET("/debian/:release/pkgs/:name/unfixed-cves", getUnfixedCvesDebian(driver))
	e.GET("/debian/:release/pkgs/:name/fixed-cves", getFixedCvesDebian(driver))
	e.GET("/ubuntu/:release/pkgs/:name/unfixed-cves", getUnfixedCvesUbuntu(driver))
	e.GET("/ubuntu/:release/pkgs/:name/fixed-cves", getFixedCvesUbuntu(driver))

	bindURL := fmt.Sprintf("%s:%s", viper.GetString("bind"), viper.GetString("port"))
	log15.Info("Listening", "URL", bindURL)

	return e.Start(bindURL)
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
		//TODO error
		cveDetail := driver.GetDebian(cveid)
		return c.JSON(http.StatusOK, &cveDetail)
	}
}

// Handler
func getUbuntuCve(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		cveid := c.Param("id")
		// TODO error
		cveDetail := driver.GetUbuntu(cveid)
		return c.JSON(http.StatusOK, &cveDetail)
	}
}

// Handler
func getMicrosoftCve(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		cveid := c.Param("id")
		//TODO error
		cveDetail := driver.GetMicrosoft(cveid)
		return c.JSON(http.StatusOK, &cveDetail)
	}
}

// Handler
func getUnfixedCvesRedhat(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		release := util.Major(c.Param("release"))
		pkgName := c.Param("name")
		cveDetail := driver.GetUnfixedCvesRedhat(release, pkgName, false)
		return c.JSON(http.StatusOK, &cveDetail)
	}
}

// Handler
func getUnfixedCvesDebian(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		release := util.Major(c.Param("release"))
		pkgName := c.Param("name")
		cveDetail := driver.GetUnfixedCvesDebian(release, pkgName)
		return c.JSON(http.StatusOK, &cveDetail)
	}
}

// Handler
func getFixedCvesDebian(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		release := util.Major(c.Param("release"))
		pkgName := c.Param("name")
		cveDetail := driver.GetFixedCvesDebian(release, pkgName)
		return c.JSON(http.StatusOK, &cveDetail)
	}
}

// Handler
func getUnfixedCvesUbuntu(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		release := util.Major(c.Param("release"))
		pkgName := c.Param("name")
		cveDetail := driver.GetUnfixedCvesUbuntu(release, pkgName)
		return c.JSON(http.StatusOK, &cveDetail)
	}
}

// Handler
func getFixedCvesUbuntu(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		release := util.Major(c.Param("release"))
		pkgName := c.Param("name")
		cveDetail := driver.GetFixedCvesUbuntu(release, pkgName)
		return c.JSON(http.StatusOK, &cveDetail)
	}
}
