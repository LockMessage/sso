package models

type App struct {
	ID     int
	Name   string
	Secret string
}

func NewApp(id int, name, secret string) *App {
	return &App{ID: id, Name: name, Secret: secret}
}
