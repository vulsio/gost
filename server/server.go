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
	"golang.org/x/xerrors"

	"github.com/vulsio/gost/db"
	"github.com/vulsio/gost/util"
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
	e.POST("/redhat/multi-cves", getRedhatMultiCve(driver))
	e.POST("/debian/multi-cves", getDebianMultiCve(driver))
	e.POST("/ubuntu/multi-cves", getUbuntuMultiCve(driver))
	e.POST("/microsoft/multi-cves", getMicrosoftMultiCve(driver))
	e.GET("/redhat/:release/pkgs/:name/unfixed-cves", getUnfixedCvesRedhat(driver))
	e.GET("/debian/:release/pkgs/:name/unfixed-cves", getUnfixedCvesDebian(driver))
	e.GET("/debian/:release/pkgs/:name/fixed-cves", getFixedCvesDebian(driver))
	e.GET("/ubuntu/:release/pkgs/:name/unfixed-cves", getUnfixedCvesUbuntu(driver))
	e.GET("/ubuntu/:release/pkgs/:name/fixed-cves", getFixedCvesUbuntu(driver))
	e.POST("/microsoft/kbids", getCveIDsByMicrosoftKBID(driver))

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
		cveDetail, err := driver.GetRedhat(cveid)
		if err != nil {
			log15.Error("Failed to get RedHat by CVEID.", "err", err)
			return err
		}
		return c.JSON(http.StatusOK, &cveDetail)
	}
}

// Handler
func getDebianCve(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		cveid := c.Param("id")
		cveDetail, err := driver.GetDebian(cveid)
		if err != nil {
			log15.Error("Failed to get Debian by CVEID.", "err", err)
			return err
		}
		return c.JSON(http.StatusOK, &cveDetail)
	}
}

// Handler
func getUbuntuCve(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		cveid := c.Param("id")
		cveDetail, err := driver.GetUbuntu(cveid)
		if err != nil {
			log15.Error("Failed to get Ubuntu by CVEID.", "err", err)
			return err
		}
		return c.JSON(http.StatusOK, &cveDetail)
	}
}

// Handler
func getMicrosoftCve(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		cveid := c.Param("id")
		cveDetail, err := driver.GetMicrosoft(cveid)
		if err != nil {
			log15.Error("Failed to get Microsoft by CVEID.", "err", err)
			return err
		}
		return c.JSON(http.StatusOK, &cveDetail)
	}
}

type cveIDs struct {
	CveIDs []string `json:"cveIDs"`
}

// Handler
func getRedhatMultiCve(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		cveIDs := cveIDs{}
		if err := c.Bind(&cveIDs); err != nil {
			return err
		}
		cveDetails, err := driver.GetRedhatMulti(cveIDs.CveIDs)
		if err != nil {
			log15.Error("Failed to get RedHat by CVEIDs.", "err", err)
			return err
		}
		return c.JSON(http.StatusOK, &cveDetails)
	}
}

// Handler
func getDebianMultiCve(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		cveIDs := cveIDs{}
		if err := c.Bind(&cveIDs); err != nil {
			return err
		}
		cveDetails, err := driver.GetDebianMulti(cveIDs.CveIDs)
		if err != nil {
			log15.Error("Failed to get Debian by CVEIDs.", "err", err)
			return err
		}
		return c.JSON(http.StatusOK, &cveDetails)
	}
}

// Handler
func getUbuntuMultiCve(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		cveIDs := cveIDs{}
		if err := c.Bind(&cveIDs); err != nil {
			return err
		}
		cveDetails, err := driver.GetUbuntuMulti(cveIDs.CveIDs)
		if err != nil {
			log15.Error("Failed to get Ubuntu by CVEIDs.", "err", err)
			return err
		}
		return c.JSON(http.StatusOK, &cveDetails)
	}
}

// Handler
func getMicrosoftMultiCve(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		cveIDs := cveIDs{}
		if err := c.Bind(&cveIDs); err != nil {
			return err
		}
		cveDetails, err := driver.GetMicrosoftMulti(cveIDs.CveIDs)
		if err != nil {
			log15.Error("Failed to get Microsoft by CVEIDs.", "err", err)
			return err
		}
		return c.JSON(http.StatusOK, &cveDetails)
	}
}

// Handler
func getUnfixedCvesRedhat(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		release := util.Major(c.Param("release"))
		pkgName := c.Param("name")
		cveDetail, err := driver.GetUnfixedCvesRedhat(release, pkgName, false)
		if err != nil {
			log15.Error("Failed to get Unfixed CVEs in RedHat", "err", err)
			return err
		}
		return c.JSON(http.StatusOK, &cveDetail)
	}
}

// Handler
func getUnfixedCvesDebian(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		release := util.Major(c.Param("release"))
		pkgName := c.Param("name")
		cveDetail, err := driver.GetUnfixedCvesDebian(release, pkgName)
		if err != nil {
			log15.Error("Failed to get Unfixed CVEs in Debian", "err", err)
			return err
		}
		return c.JSON(http.StatusOK, &cveDetail)
	}
}

// Handler
func getFixedCvesDebian(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		release := util.Major(c.Param("release"))
		pkgName := c.Param("name")
		cveDetail, err := driver.GetFixedCvesDebian(release, pkgName)
		if err != nil {
			log15.Error("Failed to get Fixed CVEs in Debian", "err", err)
			return err
		}
		return c.JSON(http.StatusOK, &cveDetail)
	}
}

// Handler
func getUnfixedCvesUbuntu(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		release := util.Major(c.Param("release"))
		pkgName := c.Param("name")
		cveDetail, err := driver.GetUnfixedCvesUbuntu(release, pkgName)
		if err != nil {
			log15.Error("Failed to get Unfixed CVEs in Ubuntu", "err", err)
			return err
		}
		return c.JSON(http.StatusOK, &cveDetail)
	}
}

// Handler
func getFixedCvesUbuntu(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		release := util.Major(c.Param("release"))
		pkgName := c.Param("name")
		cveDetail, err := driver.GetFixedCvesUbuntu(release, pkgName)
		if err != nil {
			log15.Error("Failed to get Fixed CVEs in Ubuntu", "err", err)
			return err
		}
		return c.JSON(http.StatusOK, &cveDetail)
	}
}

type msBody struct {
	Products  []string `json:"products"`
	Applied   []string `json:"applied"`
	Unapplied []string `json:"unapplied"`
}

// Handler
func getCveIDsByMicrosoftKBID(driver db.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		b := msBody{}
		if err := c.Bind(&b); err != nil {
			return err
		}
		cveIDs, err := driver.GetCvesByMicrosoftKBID(b.Products, b.Applied, b.Unapplied)
		if err != nil {
			log15.Error("Failed to get CVEIDs By KBID", "err", err)
			return err
		}
		return c.JSON(http.StatusOK, &cveIDs)
	}
}
