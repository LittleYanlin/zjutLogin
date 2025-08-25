package login

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
	"LittleYanlin/zjutLogin/encryption"
)
type LoginManager struct {
	URLLoginPage       string
	URLGetChallengeAPI string
	URLLoginAPI        string
	N     string
	VType string
	AcID  string
	Enc   string
	username        string
	password        string
	ip              string
	token           string
	info            string
	encryptedInfo   string
	md5             string
	encryptedMD5    string
	chkstr          string
	encryptedChkstr string
	loginResult     string
	client          *http.Client
}
func NewLoginManager() *LoginManager {
	serverIP := os.Getenv("ZJUT_SERVER_IP")
	if serverIP == "" {
		serverIP = "192.168.210.171"
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	return &LoginManager{
		URLLoginPage:       fmt.Sprintf("http://%s/srun_portal_pc?ac_id=1&theme=pro", serverIP),
		URLGetChallengeAPI: fmt.Sprintf("http://%s/cgi-bin/get_challenge", serverIP),
		URLLoginAPI:        fmt.Sprintf("http://%s/cgi-bin/srun_portal", serverIP),
		N:                  "200",
		VType:              "1",
		AcID:               "1",
		Enc:                "srun_bx1",
		client:             client,
	}
}
func (lm *LoginManager) Login(username, password string) error {
	lm.username = username
	lm.password = password
	fmt.Println("第一步：获取本地IP")
	maxRetries := 10
	for attempt := 1; attempt <= maxRetries; attempt++ {
		fmt.Printf("尝试获取IP (第%d次)...\n", attempt)

		if err := lm.getIP(); err != nil {
			fmt.Printf("获取IP失败 (第%d次): %v\n", attempt, err)

			if attempt < maxRetries {
				fmt.Println("等待10秒后重试...")
				time.Sleep(10 * time.Second)
				continue
			} else {
				return fmt.Errorf("获取IP失败，已达到最大重试次数 (%d次): %w", maxRetries, err)
			}
		}
		fmt.Println("成功获取IP")
		break
	}
	fmt.Println("----------------")
	fmt.Println("第二步：获取token")
	if err := lm.getToken(); err != nil {
		return fmt.Errorf("获取Token失败: %w", err)
	}
	fmt.Println("----------------")

	fmt.Println("第三步：登录")
	if err := lm.getLoginResponse(); err != nil {
		return fmt.Errorf("登录失败: %w", err)
	}
	fmt.Printf("登录结果: %s\n", lm.loginResult)
	fmt.Println("----------------")

	return nil
}

// getIP 获取本地IP
func (lm *LoginManager) getIP() error {
	fmt.Printf("正在访问登录页面: %s\n", lm.URLLoginPage)

	req, err := http.NewRequest("GET", lm.URLLoginPage, nil)
	if err != nil {
		return fmt.Errorf("创建HTTP请求失败: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.26 Safari/537.36")

	resp, err := lm.client.Do(req)
	if err != nil {
		return fmt.Errorf("访问登录页面失败: %w", err)
	}
	defer resp.Body.Close()

	// 检查HTTP状态码
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("服务器返回错误状态码: %d %s", resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应内容失败: %w", err)
	}

	if len(body) == 0 {
		return fmt.Errorf("服务器返回空响应")
	}

	fmt.Println("成功获取登录页面")

	// 解析IP
	fmt.Println("正在从登录页面解析IP地址")
	re := regexp.MustCompile(`ip\s*:\s*"([^"]+)"`)
	matches := re.FindStringSubmatch(string(body))
	if len(matches) < 2 {
		return fmt.Errorf("无法从登录页面解析IP地址，页面内容可能已改变")
	}

	lm.ip = matches[1]
	fmt.Printf("成功解析到IP地址: %s\n", lm.ip)

	return nil
}

func (lm *LoginManager) getToken() error {
	fmt.Println("开始获取token")
	params := url.Values{}
	callback := fmt.Sprintf("jsonp%d", time.Now().UnixMilli())
	params.Set("callback", callback)
	params.Set("username", lm.username)
	params.Set("ip", lm.ip)
	challengeURL := lm.URLGetChallengeAPI + "?" + params.Encode()
	req, err := http.NewRequest("GET", challengeURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.26 Safari/537.36")
	resp, err := lm.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	fmt.Println("成功获取challenge")
	fmt.Println("正在从challenge响应中解析token")
	re := regexp.MustCompile(`"challenge":"(.*?)"`)
	matches := re.FindStringSubmatch(string(body))
	if len(matches) < 2 {
		return fmt.Errorf("无法从challenge响应中解析token")
	}
	lm.token = matches[1]
	fmt.Printf("成功解析到token: %s\n", lm.token)
	return nil
}
func (lm *LoginManager) getLoginResponse() error {
	if err := lm.generateEncryptedLoginInfo(); err != nil {
		return err
	}
	fmt.Println("开始发送登录信息")
	params := url.Values{}
	callback := fmt.Sprintf("jsonp%d", time.Now().UnixMilli())
	params.Set("callback", callback)
	params.Set("action", "login")
	params.Set("username", lm.username)
	params.Set("password", lm.encryptedMD5)
	params.Set("ac_id", lm.AcID)
	params.Set("ip", lm.ip)
	params.Set("info", lm.encryptedInfo)
	params.Set("chksum", lm.encryptedChkstr)
	params.Set("n", lm.N)
	params.Set("type", lm.VType)
	loginURL := lm.URLLoginAPI + "?" + params.Encode()
	fmt.Printf("开始访问URL: %s\n", loginURL)
	req, err := http.NewRequest("GET", loginURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.26 Safari/537.36")
	resp, err := lm.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	fmt.Println("成功发送登录信息")
	// 解析登录结果
	fmt.Println("正在解析登录结果")
	fmt.Printf("登录结果: %s\n", string(body))
	re := regexp.MustCompile(`"suc_msg":"(.*?)"`)
	matches := re.FindStringSubmatch(string(body))
	if len(matches) < 2 {
		// 尝试其他可能的响应格式
		re2 := regexp.MustCompile(`"error":"(.*?)"`)
		matches2 := re2.FindStringSubmatch(string(body))
		if len(matches2) >= 2 {
			return fmt.Errorf("登录失败: %s", matches2[1])
		}
		return fmt.Errorf("无法解析登录结果，服务器响应: %s", string(body))
	}

	lm.loginResult = matches[1]
	fmt.Println("成功解析到登录结果")
	return nil
}
func (lm *LoginManager) generateEncryptedLoginInfo() error {
	lm.generateInfo()
	lm.encryptInfo()
	lm.generateMD5()
	lm.encryptMD5()
	lm.generateChksum()
	lm.encryptChksum()
	return nil
}

func (lm *LoginManager) generateInfo() {
	infoParams := map[string]string{
		"username": lm.username,
		"password": lm.password,
		"ip":       lm.ip,
		"acid":     lm.AcID,
		"enc_ver":  lm.Enc,
	}

	jsonBytes, _ := json.Marshal(infoParams)
	lm.info = strings.ReplaceAll(string(jsonBytes), " ", "")
	fmt.Printf("生成的info: %s\n", lm.info)
}

func (lm *LoginManager) encryptInfo() {
	xencodedInfo := encryption.GetXencode(lm.info, lm.token)
	base64Info := encryption.GetBase64(xencodedInfo)
	lm.encryptedInfo = "{SRBX1}" + base64Info
}

func (lm *LoginManager) generateMD5() {
	lm.md5 = encryption.GetMD5(lm.password, lm.token)
	fmt.Printf("生成的MD5: %s\n", lm.md5)
}

func (lm *LoginManager) encryptMD5() {
	lm.encryptedMD5 = "{MD5}" + lm.md5
	fmt.Printf("生成的加密MD5: %s\n", lm.encryptedMD5)
}

func (lm *LoginManager) generateChksum() {
	lm.chkstr = lm.token + lm.username
	lm.chkstr += lm.token + lm.md5
	lm.chkstr += lm.token + lm.AcID
	lm.chkstr += lm.token + lm.ip
	lm.chkstr += lm.token + lm.N
	lm.chkstr += lm.token + lm.VType
	lm.chkstr += lm.token + lm.encryptedInfo
	fmt.Printf("生成的checksum字符串: %s\n", lm.chkstr)
}

func (lm *LoginManager) encryptChksum() {
	lm.encryptedChkstr = encryption.GetSHA1(lm.chkstr)
	fmt.Printf("生成的加密checksum: %s\n", lm.encryptedChkstr)
}