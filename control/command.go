package control

import (
	"strings"
)

type Command interface {
	Name() string
	Description() []string
	Execute() error
}

var (
	commandRegistry = make(map[string]Command)
)

func RegisterCommand(cmd Command) {
	entry := strings.ToLower(cmd.Name())
	commandRegistry[entry] = cmd
}

func GetCommands() map[string]Command {
	return commandRegistry
}
