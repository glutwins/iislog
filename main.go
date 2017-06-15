package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/glutwins/scp"
)

const kFields = "#Fields: "

var leastKeys = []string{
	"date",
	"time",
	"cs-method",
	"cs-uri-stem",
	"c-ip",
	"cs(User-Agent)",
	"sc-status",
	"sc-substatus",
	"sc-win32-status",
	"sc-bytes",
	"cs-bytes",
}

type FileLog struct {
	IP      string `json:"ip"`
	Host    string `json:"host"`
	SshAddr string `json:"sshaddr"`
	SshUser string `json:"sshuser"`
	SshPass string `json:"sshpass"`
	SshFile string
	Files   map[string]int `json:"files"`
}

func (stat *FileLog) Flush() {
	b, _ := json.MarshalIndent(stat, "", "\t")
	if err := ioutil.WriteFile("config.json", b, os.ModePerm); err != nil {
		panic(err)
	}
}

var fileLogs FileLog
var fileReg = regexp.MustCompile(`LogFiles[/\\]([^/]+)[/\\]u_ex(\d{6}).log$`)

var scpHelper scp.ScpHelper

func main() {
	if b, err := ioutil.ReadFile("config.json"); err != nil {
		panic(err)
	} else if err = json.Unmarshal(b, &fileLogs); err != nil {
		panic(err)
	}

	scpHelper = scp.NewScpHelper(&scp.SshDialer{
		SSHUser: fileLogs.SshUser,
		SSHFile: fileLogs.SshFile,
		SSHPass: fileLogs.SshPass,
		SSHAddr: fileLogs.SshAddr,
	})

	scpHelper.SetLimitKB(200)
	scpHelper.SetGzipEnable(true)

	now := time.Now()
	shift := time.Hour * 24 * 30

	for siteday, _ := range fileLogs.Files {
		substr := strings.Split(siteday, "|")
		if len(substr) != 2 {
			delete(fileLogs.Files, siteday)
		} else {
			if dt, err := time.Parse("20060102", "20"+substr[1]); err != nil {
				delete(fileLogs.Files, siteday)
			} else if now.Sub(dt) > shift {
				delete(fileLogs.Files, siteday)
			}
		}
	}
	fileLogs.Flush()

	for {
		filepath.Walk("LogFiles", func(file string, info os.FileInfo, err error) error {
			now = time.Now()
			if substr := fileReg.FindAllStringSubmatch(file, -1); len(substr) != 0 {
				site := substr[0][1]
				sday := substr[0][2]

				if dt, err := time.Parse("20060102", "20"+sday); err == nil {
					if now.Sub(dt) > shift {
						os.Remove(file)
						return nil
					} else if now.Format("060102") == sday {
						return nil
					}
				}

				if _, ok := fileLogs.Files[site+"|"+sday]; ok {
					return nil
				}

				fd, err := os.Open(file)
				if err != nil {
					log.Println(err)
					return nil
				}
				defer fd.Close()
				parselog(fd, site, sday)
			}
			return nil
		})

		time.Sleep(time.Hour)
	}

	for {
		dir, err := os.Open("LogFiles")
		if err != nil {
			panic(err)
		}

		names, err := dir.Readdirnames(-1)
		for _, site := range names {
			if info, err := os.Lstat(filepath.Join("LogFiles", site)); err == nil && info.IsDir() {
			}
		}

		time.Sleep(time.Hour * 12)
	}

}

func parselog(fd *os.File, site, sday string) {
	filename := "jsonlog/" + fileLogs.Host + "_" + site + "_" + sday + ".log"
	w := bytes.NewBuffer(nil)
	r := bufio.NewReader(fd)
	var fields []string
	valid := false
	for {
		line, err := r.ReadString('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println(err)
			panic(err)
		}

		if strings.HasPrefix(line, "#") {
			if strings.HasPrefix(line, kFields) {
				valid = true
				fields = strings.Split(string([]byte(line)[len(kFields):]), " ")
				keymap := make(map[string]int)
				for i, v := range fields {
					fields[i] = strings.TrimSpace(v)
					keymap[fields[i]] = i
				}
				for _, k := range leastKeys {
					if _, ok := keymap[k]; !ok {
						log.Println("lack of key:", k)
						valid = false
						break
					}
				}
			}
		} else if valid {
			values := strings.Split(line, " ")
			valmap := map[string]string{}
			for i, v := range values {
				valmap[fields[i]] = v
			}

			tstr := valmap["date"] + " " + valmap["time"]
			dt, err := time.ParseInLocation("2006-01-02 15:04:05", tstr, time.Local)
			if err != nil {
				log.Println(err)
				continue
			}

			var wline = map[string]interface{}{}
			wline["host"] = fileLogs.Host
			wline["@timestamp"] = dt.Format("2006-01-02T15:04:05-07:00")
			wline["clientip"] = valmap["c-ip"]
			wline["size"], _ = strconv.Atoi(valmap["sc-bytes"])
			wline["csize"], _ = strconv.Atoi(valmap["cs-bytes"])
			wline["responsetime"], _ = strconv.Atoi(valmap["time-taken"])
			wline["httphost"] = site
			wline["url"] = valmap["cs-uri-stem"]
			wline["agent"] = valmap["cs(User-Agent)"]
			wline["method"] = valmap["cs-method"]
			wline["status"], _ = strconv.Atoi(valmap["sc-status"])
			wline["substatus"], _ = strconv.Atoi(valmap["sc-substatus"])
			wline["winstatus"], _ = strconv.Atoi(valmap["sc-win32-status"])

			wb, _ := json.Marshal(wline)
			w.Write(wb)
			w.WriteString("\n")
		}
	}

	if w.Len() > 0 {
		scpHelper.MustCopy(w, int64(w.Len()), filename)
	}

	fileLogs.Files[site+"|"+sday] = 1
	fileLogs.Flush()
}
