package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Метрики
var (
	ipBannedGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "fail2ban_ip_banned",
			Help: "IP ban status (1 - banned, 0 - unbanned)",
		},
		[]string{"ip", "jail", "lat", "lon"},
	)
	totalBannedIPsGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "fail2ban_total_banned_ips",
			Help: "Total number of banned IPs across all jails.",
		},
	)
	fail2banStatusGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "fail2ban_service_status",
			Help: "Status of the fail2ban service (1 if running, 0 otherwise).",
		},
	)
	fail2banVersionInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "fail2ban_version_info",
			Help: "Version of fail2ban as a string.",
		},
		[]string{"version"},
	)
	exporterStatusGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "fail2ban_exporter_status",
			Help: "Status of the fail2ban exporter service (1 if running, 0 otherwise).",
		},
	)
)

var (
	registry       = prometheus.NewRegistry()
	ipRegex        = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)
	previousBanned = make(map[string]bool)
	lock           sync.Mutex

	// Геокэш
	geoCache      = make(map[string]geoCacheEntry)
	geoCacheMutex sync.Mutex
	apiClient     = &http.Client{Timeout: 5 * time.Second}
)

type geoCacheEntry struct {
	Lat    string
	Lon    string
	Expiry time.Time
}

func init() {
	registry.MustRegister(ipBannedGauge)
	registry.MustRegister(totalBannedIPsGauge)
	registry.MustRegister(fail2banStatusGauge)
	registry.MustRegister(fail2banVersionInfo)
	registry.MustRegister(exporterStatusGauge)
}

func executeCommand(command string, args ...string) (string, error) {
	cmd := exec.Command(command, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return out.String(), err
}

func isFail2BanRunning() bool {
	serviceStatusOutput, err := executeCommand("systemctl", "is-active", "fail2ban")
	if err == nil && strings.TrimSpace(serviceStatusOutput) == "active" {
		return true
	}

	output, err := executeCommand("pgrep", "-x", "fail2ban-server")
	return err == nil && output != ""
}

func getJailList() ([]string, error) {
	output, err := executeCommand("fail2ban-client", "status")
	if err != nil {
		return nil, fmt.Errorf("failed to get jail list: %w", err)
	}

	var jails []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Jail list:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				rawJails := strings.TrimSpace(parts[1])
				jailNames := strings.Split(rawJails, ",")
				for _, jail := range jailNames {
					trimmedJail := strings.TrimSpace(jail)
					if trimmedJail != "" {
						jails = append(jails, trimmedJail)
					}
				}
			}
			break
		}
	}
	return jails, nil
}

func getBannedIPsForJail(jail string) ([]string, error) {
	output, err := executeCommand("fail2ban-client", "get", jail, "banip")
	if err != nil {
		return nil, fmt.Errorf("failed to get banned IPs for %s: %w", jail, err)
	}

	var bannedIPs []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		for _, ip := range strings.Fields(line) {
			if ipRegex.MatchString(ip) {
				bannedIPs = append(bannedIPs, ip)
			}
		}
	}
	return bannedIPs, nil
}

func getFail2BanVersion() {
	versionOutput, err := executeCommand("fail2ban-client", "--version")
	if err == nil {
		parts := strings.Split(versionOutput, " ")
		if len(parts) > 1 {
			version := strings.TrimPrefix(strings.TrimSpace(parts[1]), "v")
			fail2banVersionInfo.WithLabelValues(version).Set(1)
		}
	}
}

func getGeoData(ip string) (lat, lon string) {
	geoCacheMutex.Lock()
	defer geoCacheMutex.Unlock()

	// Проверка кэша
	if entry, exists := geoCache[ip]; exists && time.Now().Before(entry.Expiry) {
		return entry.Lat, entry.Lon
	}

	// Запрос к API
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=lat,lon", ip)
	resp, err := apiClient.Get(url)
	if err != nil {
		log.Printf("ERROR: Failed to get geo data for %s: %v", ip, err)
		return "", ""
	}
	defer resp.Body.Close()

	var data struct {
		Lat float64 `json:"lat"`
		Lon float64 `json:"lon"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		log.Printf("ERROR: Failed to parse geo data for %s: %v", ip, err)
		return "", ""
	}

	latStr := fmt.Sprintf("%.4f", data.Lat)
	lonStr := fmt.Sprintf("%.4f", data.Lon)

	// Сохранение в кэш на 24 часа
	geoCache[ip] = geoCacheEntry{
		Lat:    latStr,
		Lon:    lonStr,
		Expiry: time.Now().Add(24 * time.Hour),
	}

	return latStr, lonStr
}

func collectFail2BanMetrics() {
	exporterStatusGauge.Set(1)
	getFail2BanVersion()

	fail2banStatus := 0.0
	if isFail2BanRunning() {
		fail2banStatus = 1.0
	}
	fail2banStatusGauge.Set(fail2banStatus)

	jails, err := getJailList()
	if err != nil {
		log.Printf("Error getting jail list: %v", err)
		return
	}

	lock.Lock()
	defer lock.Unlock()

	currentBanned := make(map[string]bool)
	totalBanned := 0

	for _, jail := range jails {
		bannedIPs, err := getBannedIPsForJail(jail)
		if err != nil {
			log.Printf("Skipping jail %s: %v", jail, err)
			continue
		}

		for _, ip := range bannedIPs {
			key := fmt.Sprintf("%s:%s", jail, ip)
			currentBanned[key] = true

			lat, lon := getGeoData(ip)

			if !previousBanned[key] {
				ipBannedGauge.WithLabelValues(ip, jail, lat, lon).Set(1)
			}
		}
		totalBanned += len(bannedIPs)
	}

	// Сбрасываем метрики для разблокированных IP
	for key := range previousBanned {
		if !currentBanned[key] {
			parts := strings.SplitN(key, ":", 2)
			jail, ip := parts[0], parts[1]

			// Получаем координаты из кэша
			lat, lon := "", ""
			geoCacheMutex.Lock()
			if entry, exists := geoCache[ip]; exists {
				lat, lon = entry.Lat, entry.Lon
			}
			geoCacheMutex.Unlock()

			ipBannedGauge.WithLabelValues(ip, jail, lat, lon).Set(0)
		}
	}

	previousBanned = currentBanned
	totalBannedIPsGauge.Set(float64(totalBanned))
}

func main() {
	port := flag.Int("port", 9111, "Port to serve metrics on")
	flag.Parse()

	http.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))

	go func() {
		for range time.Tick(30 * time.Second) {
			collectFail2BanMetrics()
		}
	}()

	log.Printf("Starting fail2ban exporter on :%d", *port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", *port), nil))
}
