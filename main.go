package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/nlopes/slack"

	ps "github.com/0r3h/go-powershell"
	"github.com/0r3h/go-powershell/backend"
)

var (
	botID          string
	configFilePath = "servers.json"
	errorMsg       = "Something went wrong :/. Contact Kief."
)

type process struct {
	ID   int    `json:"Id"`
	Path string `json:"Path"`
}

type servers struct {
	Server []struct {
		Name   string `json:"name"`
		Start  string `json:"start"`
		Update string `json:"update"`
	} `json:"server"`
}

func main() {
	if len(os.Args) != 2 {
		panic("missing slack token argument")
	}

	api := slack.New(os.Args[1])
	rtm := api.NewRTM()
	go rtm.ManageConnection()

	for msg := range rtm.IncomingEvents {
		switch ev := msg.Data.(type) {
		case *slack.ConnectedEvent:
			fmt.Printf("Info: SLACK BOT CONNECTED\n")
			botID = fmt.Sprintf("<@%s>", ev.Info.User.ID)

		case *slack.MessageEvent:
			forMe, message := checkMessage(ev.Msg.Channel, ev.Msg.Text)

			if forMe {
				parseCommand(rtm, message, ev)
				fmt.Printf("Info: Received message %s\n", message)
			}

		case *slack.RTMError:
			fmt.Printf("Error: %s\n", ev.Error())

		case *slack.InvalidAuthEvent:
			fmt.Printf("Error: Invalid credentials\n")
			return

		default:
		}
	}
}

func parseCommand(rtm *slack.RTM, message string, ev *slack.MessageEvent) {
	args := strings.Split(message, " ")
	switch args[0] {
	case "status":
		commandStatus(rtm, args, ev)
	case "start":
		commandStart(rtm, args, ev)
	case "stop":
		commandStop(rtm, args, ev)
	case "update":
		commandUpdate(rtm, args, ev)
	default:
		msg := "? (status|start|stop|update)"
		rtm.SendMessage(rtm.NewOutgoingMessage(msg, ev.Msg.Channel))
	}
}

func commandStatus(rtm *slack.RTM, args []string, ev *slack.MessageEvent) {
	s, err := loadServers(configFilePath)

	if err != nil {
		log.Fatal(err)
		rtm.SendMessage(rtm.NewOutgoingMessage(errorMsg, ev.Msg.Channel))
	}

	if len(args) == 1 {
		for _, server := range s.Server {
			exe := getExePath(server.Start)
			version, err := getFileVersion(exe)
			if err != nil {
				log.Fatal(err)
				rtm.SendMessage(rtm.NewOutgoingMessage(errorMsg, ev.Msg.Channel))
			}
			status := getRunningProcessID(exe)

			if status == -1 {
				msg := fmt.Sprintf("%s is stopped @%s", server.Name, version)
				rtm.SendMessage(rtm.NewOutgoingMessage(msg, ev.Msg.Channel))
			} else {
				msg := fmt.Sprintf("%s is running @%s", server.Name, version)
				rtm.SendMessage(rtm.NewOutgoingMessage(msg, ev.Msg.Channel))
			}
		}
	} else {
		for _, server := range s.Server {
			if strings.Contains(strings.ToLower(server.Name), strings.ToLower(args[1])) {
				exe := getExePath(server.Start)
				version, err := getFileVersion(exe)
				if err != nil {
					log.Fatal(err)
					rtm.SendMessage(rtm.NewOutgoingMessage(errorMsg, ev.Msg.Channel))
				}
				status := getRunningProcessID(exe)

				if status == -1 {
					msg := fmt.Sprintf("%s is stopped @%s", server.Name, version)
					rtm.SendMessage(rtm.NewOutgoingMessage(msg, ev.Msg.Channel))
				} else {
					msg := fmt.Sprintf("%s is running @%s", server.Name, version)
					rtm.SendMessage(rtm.NewOutgoingMessage(msg, ev.Msg.Channel))
				}
			}
		}
	}
}

func commandStart(rtm *slack.RTM, args []string, ev *slack.MessageEvent) {
	s, err := loadServers(configFilePath)

	if err != nil {
		log.Fatal(err)
		rtm.SendMessage(rtm.NewOutgoingMessage(errorMsg, ev.Msg.Channel))
	}

	if len(args) == 2 {
		for _, server := range s.Server {
			if strings.ToLower(server.Name) == strings.ToLower(args[1]) {
				exe := getExePath(server.Start)
				if _, err := os.Stat(exe); os.IsNotExist(err) {
					msg := fmt.Sprintf("%s is not installed", server.Name)
					rtm.SendMessage(rtm.NewOutgoingMessage(msg, ev.Msg.Channel))
					break
				}
				version, err := getFileVersion(exe)
				if err != nil {
					log.Fatal(err)
					rtm.SendMessage(rtm.NewOutgoingMessage(errorMsg, ev.Msg.Channel))
				}
				status := getRunningProcessID(exe)

				if status != -1 {
					msg := fmt.Sprintf("%s is already running @%s", server.Name, version)
					rtm.SendMessage(rtm.NewOutgoingMessage(msg, ev.Msg.Channel))
				} else {
					go runScript(server.Start)
					msg := fmt.Sprintf("%s started @%s", server.Name, version)
					rtm.SendMessage(rtm.NewOutgoingMessage(msg, ev.Msg.Channel))
				}
				break
			}
		}
	} else {
		msg := fmt.Sprintf("? (start <server name>) (start qa1)")
		rtm.SendMessage(rtm.NewOutgoingMessage(msg, ev.Msg.Channel))
	}
}

func commandStop(rtm *slack.RTM, args []string, ev *slack.MessageEvent) {
	s, err := loadServers(configFilePath)

	if err != nil {
		log.Fatal(err)
		rtm.SendMessage(rtm.NewOutgoingMessage(errorMsg, ev.Msg.Channel))
	}

	if len(args) == 2 {
		for _, server := range s.Server {
			if strings.ToLower(server.Name) == strings.ToLower(args[1]) {
				exe := getExePath(server.Start)
				if _, err := os.Stat(exe); os.IsNotExist(err) {
					msg := fmt.Sprintf("%s is not installed", server.Name)
					rtm.SendMessage(rtm.NewOutgoingMessage(msg, ev.Msg.Channel))
					break
				}
				status := getRunningProcessID(exe)

				if status == -1 {
					msg := fmt.Sprintf("%s is not running", server.Name)
					rtm.SendMessage(rtm.NewOutgoingMessage(msg, ev.Msg.Channel))
				} else {
					stopProcess(getRunningProcessID(exe))
					msg := fmt.Sprintf("%s stopped", server.Name)
					rtm.SendMessage(rtm.NewOutgoingMessage(msg, ev.Msg.Channel))
				}
				break
			}
		}
	} else {
		msg := fmt.Sprintf("? (stop <server name>) (stop qa1)")
		rtm.SendMessage(rtm.NewOutgoingMessage(msg, ev.Msg.Channel))
	}
}

func commandUpdate(rtm *slack.RTM, args []string, ev *slack.MessageEvent) {
	s, err := loadServers(configFilePath)

	if err != nil {
		log.Fatal(err)
		rtm.SendMessage(rtm.NewOutgoingMessage(errorMsg, ev.Msg.Channel))
	}

	if len(args) == 2 {
		for _, server := range s.Server {
			if strings.ToLower(server.Name) == strings.ToLower(args[1]) {
				exe := getExePath(server.Start)
				status := getRunningProcessID(exe)

				if status == -1 {
					msg := fmt.Sprintf("%s is updating", server.Name)
					rtm.SendMessage(rtm.NewOutgoingMessage(msg, ev.Msg.Channel))

					runScript(server.Update)

					version, err := getFileVersion(exe)
					if err != nil {
						log.Fatal(err)
						rtm.SendMessage(rtm.NewOutgoingMessage(errorMsg, ev.Msg.Channel))
					}

					msg = fmt.Sprintf("%s is updated to %s", server.Name, version)
					rtm.SendMessage(rtm.NewOutgoingMessage(msg, ev.Msg.Channel))
				} else {
					stopProcess(getRunningProcessID(exe))
					msg := fmt.Sprintf("%s stopped", server.Name)
					rtm.SendMessage(rtm.NewOutgoingMessage(msg, ev.Msg.Channel))

					msg = fmt.Sprintf("%s is updating", server.Name)
					rtm.SendMessage(rtm.NewOutgoingMessage(msg, ev.Msg.Channel))

					runScript(server.Update)

					version, err := getFileVersion(exe)
					if err != nil {
						log.Fatal(err)
						rtm.SendMessage(rtm.NewOutgoingMessage(errorMsg, ev.Msg.Channel))
					}

					msg = fmt.Sprintf("%s is updated to %s", server.Name, version)
					rtm.SendMessage(rtm.NewOutgoingMessage(msg, ev.Msg.Channel))

					go runScript(server.Start)
					msg = fmt.Sprintf("%s started @%s", server.Name, version)
					rtm.SendMessage(rtm.NewOutgoingMessage(msg, ev.Msg.Channel))
				}
				break
			}
		}
	} else {
		msg := fmt.Sprintf("? (update <server name>) (update qa1)")
		rtm.SendMessage(rtm.NewOutgoingMessage(msg, ev.Msg.Channel))
	}
}

func loadServers(path string) (servers, error) {
	var s servers
	f, err := os.Open(path)
	if err != nil {
		return s, err
	}
	defer f.Close()

	parser := json.NewDecoder(f)
	err = parser.Decode(&s)

	return s, err
}

// Returns file version of file with path
func getFileVersion(path string) (version string, err error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		version := "not installed"
		return version, nil
	}

	back := &backend.Local{}

	shell, err := ps.New(back)
	if err != nil {
		return version, err
	}
	defer shell.Exit()

	command := fmt.Sprintf("(Get-Item %s).VersionInfo.FileVersion", path)

	version, _, err = shell.Execute(command)
	if err != nil {
		return version, err
	}

	return version, err
}

// Return processes that have Squad in their name
func getProcesses() []process {
	back := &backend.Local{}

	shell, err := ps.New(back)
	if err != nil {
		log.Fatal(err)
	}
	defer shell.Exit()

	stdout, _, err := shell.Execute("Get-Process *Squad* | Select-Object -Property Id, Path | ConvertTo-Csv")
	if err != nil {
		log.Fatal(err)
	}

	var processes []process

	for i, line := range strings.Split(stdout, "\r\n") {
		if i >= 2 && len(line) > 0 {
			value := strings.Split(line, ",")

			var p process
			p.ID, err = strconv.Atoi(strings.Trim(value[0], "\""))
			p.Path = strings.Trim(value[1], "\"")

			processes = append(processes, p)
		}
	}

	return processes
}

// Stop a process by process ID
func stopProcess(ID int) {
	back := &backend.Local{}

	shell, err := ps.New(back)
	if err != nil {
		log.Fatal(err)
	}
	defer shell.Exit()

	_, _, err = shell.Execute(fmt.Sprintf("Stop-Process -Id %d", ID))
	if err != nil {
		log.Fatal(err)
	}
}

// Returns a process ID if process with path is running, otherwise returns -1
func getRunningProcessID(path string) int {
	processID := -1
	runningProcesses := getProcesses()

	for _, p := range runningProcesses {
		processID = -1

		if strings.ToLower(p.Path) == strings.ToLower(path) {
			processID = p.ID
			break
		}
	}

	return processID
}

// Parses full path to Squad exe from start script
func getExePath(path string) string {
	file := getFileContents(path)

	r := regexp.MustCompile(`cd "(.*)"\r\nstart (.*\.exe)`)
	parse := r.FindStringSubmatch(file)

	var exePath string

	if parse[1][len(parse[1])-1:] == "\\" {
		exePath = fmt.Sprintf("%s%s", parse[1], parse[2])
	} else {
		exePath = fmt.Sprintf("%s\\%s", parse[1], parse[2])
	}

	return exePath
}

// Return contents in file with path as string
func getFileContents(path string) string {
	f, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	return string(f)
}

// Executes a script at path and returns its output when finished
func runScript(path string) string {
	cmd := exec.Command("cmd.exe", "/C", path)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	return out.String()
}

func checkMessage(channel string, input string) (forMe bool, output string) {
	forMe = false
	output = ""

	if string(channel[0]) == "D" {
		forMe = true
	}

	if strings.Contains(input, botID) {
		forMe = true
	}

	output = cleanBotMentions(input)

	return forMe, output
}

func cleanBotMentions(m string) string {
	m = strings.Replace(m, botID, "", -1)
	m = strings.Trim(m, " ")

	return m
}
