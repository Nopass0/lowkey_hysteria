package xray

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	voidorm "github.com/Nopass0/void_go"

	"hysteria_server/db"
	"hysteria_server/heartbeat"
	"hysteria_server/telemetry"
)

type XrayConfig struct {
	Port  int
	Users []string
}

const xrayConfigTmpl = `
{
  "log": {
    "loglevel": "warning"
  },
  "stats": {},
  "api": {
    "tag": "api",
    "services": [
      "StatsService"
    ]
  },
  "routing": {
    "rules": [
      {
        "type": "field",
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api"
      }
    ]
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserUplink": true,
        "statsUserDownlink": true,
        "statsUserOnline": true
      }
    }
  },
  "inbounds": [
    {
      "tag": "api",
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      }
    },
    {
      "tag": "vless-in",
      "port": {{.Port}},
      "protocol": "vless",
      "settings": {
        "clients": [
          {{range $i, $u := .Users}}{{if $i}},{{end}}
          {
            "id": "{{$u}}",
            "email": "{{$u}}",
            "level": 0,
            "flow": "xtls-rprx-vision"
          }
          {{end}}
        ],
        "decryption": "none"
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "google.com:443",
          "xver": 0,
          "serverNames": [
            "google.com"
          ],
          "privateKey": "97tkV3UQpZrSOQ2fPe1ZDGUc7Ew7Azibfkgtzc46To0",
          "shortIds": [
            "e12b6c973e573780"
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
`

var (
	cmd *exec.Cmd

	trafficStatRe = regexp.MustCompile(`^user>>>(.+?)>>>traffic>>>(uplink|downlink)$`)
	onlineStatRe  = regexp.MustCompile(`^user>>>(.+?)>>>(?:online|connection|connections)$`)
)

func SyncUsers(port int) {
	var lastUsers []string

	for {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		rows, err := db.FindMany(ctx, "subscriptions", voidorm.NewQuery().WhereNode(voidorm.QueryNode{
			OR: []voidorm.QueryNode{
				{Field: "isLifetime", Op: voidorm.Eq, Value: true},
				{Field: "activeUntil", Op: voidorm.Gte, Value: time.Now().UTC()},
			},
		}))
		cancel()
		if err != nil {
			log.Printf("[Xray] Subscription query error: %v", err)
			time.Sleep(30 * time.Second)
			continue
		}

		seen := make(map[string]struct{}, len(rows))
		currentUsers := make([]string, 0, len(rows))
		for _, row := range rows {
			userID := db.AsString(row, "userId")
			if userID == "" {
				continue
			}
			if _, ok := seen[userID]; ok {
				continue
			}
			seen[userID] = struct{}{}
			currentUsers = append(currentUsers, userID)
		}
		sort.Strings(currentUsers)

		if !sameUsers(currentUsers, lastUsers) {
			log.Printf("[Xray] Active users changed (%d total), reconfiguring Xray", len(currentUsers))
			if err := restartXray(currentUsers, port); err != nil {
				log.Printf("[Xray] Failed to restart Xray: %v", err)
			} else {
				lastUsers = currentUsers
			}
		}

		time.Sleep(30 * time.Second)
	}
}

func StartStatsPoller() {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	lastUsers := map[string]struct{}{}

	for range ticker.C {
		stats, err := queryStats()
		if err != nil {
			log.Printf("[Xray] Stats query failed: %v", err)
			continue
		}

		type userAgg struct {
			up     int64
			down   int64
			online int64
		}

		perUser := map[string]*userAgg{}
		totalOnline := int64(0)
		sawOnlineStat := false

		for _, item := range stats.Stat {
			if m := trafficStatRe.FindStringSubmatch(item.Name); m != nil {
				userID := m[1]
				dir := m[2]
				if _, ok := perUser[userID]; !ok {
					perUser[userID] = &userAgg{}
				}
				if dir == "uplink" {
					perUser[userID].up = item.IntValue()
				} else {
					perUser[userID].down = item.IntValue()
				}
				continue
			}
			if m := onlineStatRe.FindStringSubmatch(item.Name); m != nil {
				userID := m[1]
				if _, ok := perUser[userID]; !ok {
					perUser[userID] = &userAgg{}
				}
				perUser[userID].online = item.IntValue()
				totalOnline += item.IntValue()
				sawOnlineStat = true
			}
		}

		if !sawOnlineStat {
			for userID, agg := range perUser {
				telemetry.ApplyVLESSUserTraffic(userID, heartbeat.ServerID(), agg.up, agg.down)
			}
			telemetry.SyncVLESSSessionCountsFromDB(heartbeat.ServerID())
			continue
		}

		currentUsers := make(map[string]struct{}, len(perUser))
		for userID, agg := range perUser {
			currentUsers[userID] = struct{}{}
			telemetry.ApplyVLESSUserSnapshot(userID, heartbeat.ServerID(), agg.up, agg.down, agg.online)
		}
		for userID := range lastUsers {
			if _, ok := currentUsers[userID]; !ok {
				telemetry.ResetVLESSUserActive(userID, heartbeat.ServerID())
			}
		}
		lastUsers = currentUsers
		telemetry.SetVLESSActive(totalOnline)
	}
}

func sameUsers(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func restartXray(users []string, port int) error {
	tmpl, err := template.New("config").Parse(xrayConfigTmpl)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, XrayConfig{Port: port, Users: users}); err != nil {
		return err
	}
	if err := os.WriteFile("xray_config.json", buf.Bytes(), 0644); err != nil {
		return err
	}

	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}

	cmd = exec.Command("xray", "run", "-c", "xray_config.json")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}
	go streamXrayOutput(stdout, false)
	go streamXrayOutput(stderr, true)
	log.Printf("[Xray] Started new xray process with PID %d", cmd.Process.Pid)
	return nil
}

type statsResponse struct {
	Stat []statsItem `json:"stat"`
}

type statsItem struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
}

func (s statsItem) IntValue() int64 {
	if len(s.Value) == 0 {
		return 0
	}
	if s.Value[0] == '"' {
		var value string
		if err := json.Unmarshal(s.Value, &value); err == nil {
			n, _ := strconv.ParseInt(value, 10, 64)
			return n
		}
		return 0
	}

	var number json.Number
	if err := json.Unmarshal(s.Value, &number); err == nil {
		n, _ := number.Int64()
		return n
	}

	var fallback int64
	_ = json.Unmarshal(s.Value, &fallback)
	return fallback
}

func queryStats() (*statsResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "xray", "api", "statsquery", "--server=127.0.0.1:10085").Output()
	if err != nil {
		return nil, err
	}

	var resp statsResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func streamXrayOutput(reader io.Reader, isErr bool) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		userID, remoteAddr, network, destination, ok := parseAccessLogLine(line)
		if ok {
			telemetry.ObserveVLESSAccess(
				userID,
				heartbeat.ServerID(),
				heartbeat.ServerIP(),
				remoteAddr,
				destination,
				network,
			)
			continue
		}

		if strings.TrimSpace(line) == "" {
			continue
		}

		if isErr {
			fmt.Fprintln(os.Stderr, line)
		} else {
			fmt.Fprintln(os.Stdout, line)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[Xray] Output stream error: %v", err)
	}
}

func parseAccessLogLine(line string) (userID, remoteAddr, network, destination string, ok bool) {
	fromIndex := strings.Index(line, "from ")
	if fromIndex == -1 {
		return "", "", "", "", false
	}
	acceptedIndex := strings.Index(line[fromIndex+5:], " accepted ")
	if acceptedIndex == -1 {
		return "", "", "", "", false
	}
	acceptedIndex += fromIndex + 5

	emailIndex := strings.LastIndex(line, " email: ")
	if emailIndex == -1 || emailIndex <= acceptedIndex {
		return "", "", "", "", false
	}

	remoteAddr = strings.TrimSpace(line[fromIndex+5 : acceptedIndex])
	remoteAddr = strings.TrimPrefix(strings.TrimPrefix(remoteAddr, "tcp:"), "udp:")
	userID = strings.TrimSpace(line[emailIndex+8:])
	if userID == "" {
		return "", "", "", "", false
	}

	destPart := strings.TrimSpace(line[acceptedIndex+10 : emailIndex])
	colonIndex := strings.Index(destPart, ":")
	if colonIndex == -1 {
		return "", "", "", "", false
	}

	network = strings.TrimSpace(destPart[:colonIndex])
	destination = strings.TrimSpace(destPart[colonIndex+1:])
	if network == "" || destination == "" {
		return "", "", "", "", false
	}

	return userID, remoteAddr, network, destination, true
}
