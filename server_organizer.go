package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte("SUPER_SECRET_COOKIE_KEY"))

type Task struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Deadline    time.Time `json:"deadline"`
	Complete    bool      `json:"complete"`
}

func main_page(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-user")
	resp, err := http.Get(fmt.Sprintf("http://localhost:8080/tasks?email=%s", session.Values["email"]))
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()

	var tasks []Task
	body, _ := io.ReadAll(resp.Body)
	err = json.Unmarshal(body, &tasks)
	if err != nil {
		fmt.Println(err)
	}

	var datt = make([]struct {
		Task Task
		Time string
	}, len(tasks))

	for i, task := range tasks {
		datt[i].Task = task
		datt[i].Time = task.Deadline.Format("01-02-06 15:04")
	}

	pageVariables := struct {
		Datt []struct {
			Task Task
			Time string
		}
		Message string
	}{
		Datt:    datt,
		Message: session.Values["message"].(string),
	}

	data, _ := os.ReadFile("content/main.html")
	tmpl, _ := template.New("main").Parse(string(data))
	tmpl.Execute(w, pageVariables)
	return
}

func tasker(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-user")

	datt := Task{}

	if r.Method == "POST" {
		r.ParseForm()

		deadline, err := time.Parse("2006-01-02T15:04", r.FormValue("deadline"))
		if err != nil {
			fmt.Println(err)
			session.Values["message"] = fmt.Sprint(err)
			session.Save(r, w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		if r.FormValue("id") != "" {
			datt = Task{
				ID:          r.FormValue("id"),
				Title:       r.FormValue("title"),
				Description: r.FormValue("description"),
				Deadline:    deadline,
				Complete:    false,
			}

			jsonData, _ := json.MarshalIndent(datt, " ", "  ")

			email := url.QueryEscape(session.Values["email"].(string))

			resp, err := http.Post(fmt.Sprintf("http://localhost:8080/updateTask?email=%s", email), "application/json", bytes.NewBuffer(jsonData))
			if err == nil {
				defer resp.Body.Close()
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			} else {
				fmt.Println(err)
				defer resp.Body.Close()
				session.Values["message"] = fmt.Sprint(err)
				session.Save(r, w)
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}

		} else {
			deadlineRFC3339 := deadline.Format(time.RFC3339)

			email := url.QueryEscape(session.Values["email"].(string))

			resp, err := http.Get(fmt.Sprintf("http://localhost:8080/createTask?email=%s&title=%s&description=%s&deadline=%s", email, r.FormValue("title"), r.FormValue("description"), deadlineRFC3339))
			if err != nil {
				fmt.Println(err)
				session.Values["message"] = fmt.Sprint(err)
				session.Save(r, w)
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
			if resp.StatusCode != http.StatusOK {
				session.Values["message"] = "Не удалось создать задачу"
				session.Save(r, w)
			}
			http.Redirect(w, r, "/", http.StatusSeeOther)
			/*defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				session.Values["message"] = fmt.Sprint(err)
				session.Save(r, w)
				http.Redirect(w, r, "/reg", http.StatusSeeOther)
				return
			}
			session.Values["message"] = string(body)
			session.Save(r, w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return*/
		}

	} else {

		id := r.URL.Query().Get("id")
		if id != "" {
			email := url.QueryEscape(session.Values["email"].(string))
			resp, err := http.Get(fmt.Sprintf("http://localhost:8080/task?task_id=%s&email=%s", id, email))
			if err != nil {
				fmt.Println(err, "*****")
				session.Values["message"] = fmt.Sprint(err, "*****")
				session.Save(r, w)
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			err = json.Unmarshal(body, &datt)
			if err != nil {
				fmt.Println(err, "/////")
				session.Values["message"] = fmt.Sprint(err, "//////")
				session.Save(r, w)
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
		}
		if datt.Deadline.Before(time.Now()) {
			datt.Deadline = time.Now().Add(time.Hour)
		}

		pageVariables := struct {
			MinDateTime string
			DateTime    string
			Datt        Task
			Message     string
		}{
			MinDateTime: time.Now().Add(time.Hour).Format("2006-01-02T15:04"),
			DateTime:    datt.Deadline.Format("2006-01-02T15:04"),
			Datt:        datt,
			Message:     session.Values["message"].(string),
		}

		data, _ := os.ReadFile("content/tasker.html")
		tmpl, _ := template.New("tasker").Parse(string(data))
		tmpl.Execute(w, pageVariables)
		return
	}
}

func register(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-user")

	if r.Method == "POST" {
		if r.FormValue("code") == "" {
			email := url.QueryEscape(r.FormValue("email"))
			password := url.QueryEscape(r.FormValue("password"))
			resp, err := http.Get(fmt.Sprintf("http://localhost:8080/register?email=%s&password=%s", email, password))
			if err != nil {
				session.Values["message"] = fmt.Sprint(err)
				session.Save(r, w)
				http.Redirect(w, r, "/reg", http.StatusSeeOther)
				return
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				session.Values["message"] = fmt.Sprint(err)
				session.Save(r, w)
				http.Redirect(w, r, "/reg", http.StatusSeeOther)
				return
			}
			if string(body) != "true" {
				session.Values["message"] = string(body)
				session.Save(r, w)
				http.Redirect(w, r, "/reg", http.StatusSeeOther)
				return
			}
			session.Values["message"] = "На указанную вами почту пришел код, чтобы закончить регистрацию введите его в поле ниже"
			session.Values["email_reg"] = r.FormValue("email")
			session.Save(r, w)
			http.Redirect(w, r, "/reg", http.StatusSeeOther)
			return
		}
		email := url.QueryEscape(session.Values["email_reg"].(string))
		code := url.QueryEscape(r.FormValue("code"))
		resp, err := http.Get(fmt.Sprintf("http://localhost:8080/regFinish?code=%s&email=%s", code, email))
		if err != nil {
			session.Values["message"] = fmt.Sprint(err)
			session.Save(r, w)
			http.Redirect(w, r, "/reg", http.StatusSeeOther)
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			session.Values["message"] = fmt.Sprint(err)
			session.Save(r, w)
			http.Redirect(w, r, "/reg", http.StatusSeeOther)
			return
		}
		if string(body) == "true" {
			session.Options.MaxAge = -1
			session.Save(r, w)
			http.Redirect(w, r, "/auth", http.StatusSeeOther)
			return
		} else if string(body) == "time out" {
			session.Values["message"] = "Ваш код истёк"
			session.Values["email_reg"] = ""
			session.Save(r, w)
			http.Redirect(w, r, "/reg", http.StatusSeeOther)
			return
		}
		session.Values["message"] = "Неверный код"
		session.Save(r, w)
		http.Redirect(w, r, "/reg", http.StatusSeeOther)
		return

	}
	data, err := os.ReadFile("content/reg.html")
	if err != nil {
		fmt.Println(err)
		return
	}
	tmpl, err := template.New("reg").Parse(string(data))
	if err != nil {
		fmt.Println(err)
		return
	}
	tmpl.Execute(w, session.Values["message"])

	return
}

func authorize(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-user")

	if r.Method == "POST" {
		email := url.QueryEscape(r.FormValue("email"))
		password := url.QueryEscape(r.FormValue("password"))
		resp, err := http.Get(fmt.Sprintf("http://localhost:8080/login?email=%s&password=%s", email, password))
		if err != nil {
			session.Values["message"] = fmt.Sprint(err)
			session.Save(r, w)
			http.Redirect(w, r, "/auth", http.StatusSeeOther)
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			session.Values["message"] = fmt.Sprint(err)
			session.Save(r, w)
			http.Redirect(w, r, "/auth", http.StatusSeeOther)
			return
		}
		if string(body) != "true" {
			session.Values["message"] = string(body)
			session.Save(r, w)
			http.Redirect(w, r, "/auth", http.StatusSeeOther)
			return
		}
		session.Values["message"] = ""
		session.Values["email"] = r.FormValue("email")
		session.Values["pswrd"] = r.FormValue("password")
		session.Save(r, w)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	data, err := os.ReadFile("content/auth.html")
	if err != nil {
		fmt.Println(err)
		return
	}
	tmpl, err := template.New("auth").Parse(string(data))
	if err != nil {
		fmt.Println(err)
		return
	}
	tmpl.Execute(w, session.Values["message"])
	return
}

func Loggin_check(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/content/") {
			next.ServeHTTP(w, r)
			return
		}
		session, _ := store.Get(r, "cookie-user")

		email := ""
		password := ""

		if session.Values["email"] == nil || session.Values["pswrd"] == nil {

		} else {
			email = url.QueryEscape(session.Values["email"].(string))
			password = url.QueryEscape(session.Values["pswrd"].(string))
		}

		resp, err := http.Get(fmt.Sprintf("http://localhost:8080/login?email=%s&password=%s", email, password))
		var body = []byte("false")
		if err == nil {
			defer resp.Body.Close()
			body, _ = io.ReadAll(resp.Body)
		}
		if string(body) == "true" && (r.URL.Path == "/reg" || r.URL.Path == "/auth") {
			http.Redirect(w, r, "/", http.StatusSeeOther)

			return
		} else if string(body) == "true" || r.URL.Path == "/auth" || r.URL.Path == "/reg" {
			next.ServeHTTP(w, r)

			return
		} else {
			session.Options.MaxAge = -1
			session.Save(r, w)
			http.Redirect(w, r, "/auth", http.StatusSeeOther)

			return
		}
	})
}

func exit(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-user")
	session.Options.MaxAge = -1
	session.Save(r, w)
	http.Redirect(w, r, "/auth", http.StatusSeeOther)
	return
}

func com_uncom(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-user")

	datt := Task{}

	id := r.URL.Query().Get("id")
	if id != "" {
		email := url.QueryEscape(session.Values["email"].(string))
		resp, err := http.Get(fmt.Sprintf("http://localhost:8080/task?task_id=%s&email=%s", id, email))
		if err != nil {
			fmt.Println(err)
			session.Values["message"] = "Ошибка сервера"
			session.Save(r, w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		err = json.Unmarshal(body, &datt)
		if err != nil {
			fmt.Println(err)
			session.Values["message"] = "Ошибка сервера"
			session.Save(r, w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}
	if r.URL.Query().Get("val") == "1" {
		datt.Complete = true
	} else {
		datt.Complete = false
	}
	jsonData, _ := json.MarshalIndent(datt, " ", "  ")

	resp, err := http.Post(fmt.Sprintf("http://localhost:8080/updateTask?email=%s", session.Values["email"]), "application/json", bytes.NewBuffer(jsonData))
	if err == nil {
		defer resp.Body.Close()
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	} else {
		fmt.Println(err)
		defer resp.Body.Close()
		session.Values["message"] = "Ошибка сервера"
		session.Save(r, w)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
}

func del(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-user")
	id := r.URL.Query().Get("id")
	email := url.QueryEscape(session.Values["email"].(string))
	resp, err := http.Get(fmt.Sprintf("http://localhost:8080/deleteTask?task_id=%s&email=%s", id, email))
	if err != nil || resp.StatusCode != http.StatusOK {
		fmt.Println(err)
		session.Values["message"] = "Ошибка сервера"
		session.Save(r, w)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	session.Values["message"] = string(body)
	fmt.Println(string(body))
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func del_user(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-user")
	email := url.QueryEscape(session.Values["email"].(string))
	resp, err := http.Get(fmt.Sprintf("http://localhost:8080/delUser?email=%s", email))
	if err != nil || resp.StatusCode != http.StatusOK {
		session.Values["message"] = "Ошибка сервера"
		session.Save(r, w)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func passwrd(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-user")
	if r.Method == "POST" {
		email := url.QueryEscape(session.Values["email"].(string))
		password := url.QueryEscape(r.FormValue("password"))
		resp, err := http.Get(fmt.Sprintf("http://localhost:8080/changePassword?email=%s&new_password=%s", email, password))
		if err != nil {
			session.Values["message"] = "Ошибка сервера"
			session.Save(r, w)
			http.Redirect(w, r, "/ChangePassword", http.StatusSeeOther)
			return
		}
		if resp.StatusCode != http.StatusOK {
			session.Values["message"] = "Не удалось поменять пароль"
			session.Save(r, w)
			http.Redirect(w, r, "/ChangePassword", http.StatusSeeOther)
			return

		}
		session.Values["message"] = "Пароль успешно изменён"
		session.Save(r, w)
		http.Redirect(w, r, "/auth", http.StatusSeeOther)
		return
	}
	data, _ := os.ReadFile("content/password.html")
	tmpl, _ := template.New("password").Parse(string(data))
	tmpl.Execute(w, session.Values["message"])
	return
}

func main() {
	router := mux.NewRouter()

	router.HandleFunc("/", main_page)
	router.HandleFunc("/reg", register)
	router.HandleFunc("/auth", authorize)
	router.HandleFunc("/exit", exit)
	router.HandleFunc("/new_task", tasker)
	router.HandleFunc("/complete", com_uncom)
	router.HandleFunc("/delete", del)
	router.HandleFunc("/ChangePassword", passwrd)
	router.HandleFunc("/DeleteAccount", del_user)
	fs := http.FileServer(http.Dir("./content"))
	router.PathPrefix("/content/").Handler(http.StripPrefix("/content/", fs))

	router.Use(Loggin_check)
	http.ListenAndServe(":8081", router)
}
