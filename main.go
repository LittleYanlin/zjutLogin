package main

import (
	"LittleYanlin/zjutLogin/login"
	"fmt"
	"io"
	"log"
	"os"
	"github.com/joho/godotenv"
)

func main() {
	logFile, err := os.OpenFile("zjutLogin.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		log.Fatalf("无法创建日志文件: %v", err)
	}
	defer logFile.Close()
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(multiWriter)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	err = godotenv.Load()
	if err != nil {
		log.Println("没有找到.env文件，将使用系统环境变量")
	}
	username := os.Getenv("ZJUT_USERNAME")
	password := os.Getenv("ZJUT_PASSWORD")
	if username == "" {
		log.Fatal("请设置环境变量 ZJUT_USERNAME 或在.env文件中配置")
	}
	if password == "" {
		log.Fatal("请设置环境变量 ZJUT_PASSWORD 或在.env文件中配置")
	}
	fmt.Printf("学号：%s",username)
	fmt.Printf("密码：%s\n",password)
	lm := login.NewLoginManager()
	log.Println("开始登录...")
	err = lm.Login(username, password)
	if err != nil {
		log.Fatalf("登录失败: %v", err)
	}
	log.Println("登录完成")
	log.Println("程序执行结束")
}
