package main

import (
	"cert"
	"errors"
	"flag"
	"fmt"
	"gopass"
	"os"
	"time"
	"uuid"
)

const (
	WORKDIR = "./pki"
)

var (
	bShowHelp    = flag.Bool("h", false, "Show this Help")
	bInitProject = flag.Bool("I", false, "初始化项目，新建CA证书") // 是否初始化项目
	bCreateCert  = flag.Bool("new", false, "签发证书")
	bEcc         = flag.Bool("ecc", false, "是否创建ECC类型的证书, 与-c命令搭配使用")
	sCN          = flag.String("CN", "", "CommonName，证书绑定域名, 与-c命令搭配使用")
	bPassword    = flag.Bool("p", false, "签发证书的私钥文件是否需要密码保护")
	sFormat      = flag.String("f", "pkcs1", "私钥文件格式，支持`pkcs1`和`pkcs8`")
	iDays        = flag.Int("d", 365, "证书有效期, 与-c命令搭配使用")
)

func showHelp() {
	fmt.Fprintf(os.Stderr, "Usage: easyCA [-hI] [-new] [-ecc] [-p password] [-CN commonName] [-d days]\n\nOptions:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nExample:\n")
	fmt.Fprintf(os.Stderr, "   %-35s%s\n", "easyCA -I -d 3650", "初始化项目")
	fmt.Fprintf(os.Stderr, "   %-35s%s\n", "easyCA -new -CN foo.jdcloud.local", "创建CommonName为foo.jdcloud.local的服务器端证书")
	fmt.Fprintf(os.Stderr, "\n")
}

func getPass(prompt string) (string, error) {
	passwd, err := gopass.GetPass(prompt)
	if err != nil {
		return "", err
	}
	passwd2, err := gopass.GetPass("Re-" + prompt)
	if err != nil {
		return "", err
	}
	if passwd != passwd2 {
		return "", errors.New("Invalid password.")
	}
	return passwd, nil
}

func createCA() error {
	passWord, err := getPass("Enter New CA Key Passphrase: ")
	if err != nil {
		return err
	}

	k, err := cert.GenerateSelfSignedCertificate("rsa", true, "", 3650)
	if err != nil {
		return err
	}

	if err := k.WritePrivateKey(WORKDIR+"/private/ca.key", passWord, *sFormat); err != nil {
		return err
	}

	if err := k.WriteCertificate(WORKDIR + "/ca.crt"); err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "初始化CA私钥文件: %s\n", WORKDIR+"/private/ca.key")
	fmt.Fprintf(os.Stdout, "初始化CA证书文件: %s\n", WORKDIR+"/ca.crt")
	return nil
}

func newCert() error {
	/** check ContentName **/
	if *sCN == "" {
		return fmt.Errorf("Please set `-n CommonName` argument.")
	}

	ca := &cert.KeyPair{}
	if err := ca.LoadPrivateKey(WORKDIR + "/private/ca.key"); err != nil {
		return err
	}
	if err := ca.LoadCertificate(WORKDIR + "/ca.crt"); err != nil {
		return err
	}

	algo := "rsa"
	if bEcc != nil && *bEcc == true {
		algo = "ecc"
	}
	k, err := cert.GenerateCASignedCertificate(algo, *sCN, ca, *iDays)
	if err != nil {
		return err
	}

	password := ""
	if bPassword != nil && *bPassword == true {
		if password, err = getPass("Enter New Key Passphrase: "); err != nil {
			return err
		}
	}

	fileName := WORKDIR + "/issued/" + *sCN + time.Now().Format("-20060102150405-") + uuid.Uuid(8)
	os.MkdirAll(WORKDIR+"/issued", 0755)
	if err := k.WritePrivateKey(fileName+".key", password, *sFormat); err != nil {
		return err
	}
	if err := k.WriteCertificate(fileName + ".crt"); err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "创建私钥文件: %s\n", fileName+".key")
	fmt.Fprintf(os.Stdout, "创建证书文件: %s\n", fileName+".crt")
	return nil
}

func initProject() error {
	fmt.Fprintf(os.Stdout, "初始化CA环境。。。\n")

	fi, err := os.Stat(WORKDIR)
	if err != nil && os.IsNotExist(err) {
		os.MkdirAll(WORKDIR+"/private", 0755)
		return createCA()
	} else if err != nil {
		return err
	} else {
		if fi.IsDir() {
			fmt.Fprintf(os.Stderr, "Directory `./pki` is already existed.\nNow, check CA certificate.")
			ca := &cert.KeyPair{}
			if err := ca.LoadPrivateKey(WORKDIR + "/private/ca.key"); err != nil {
				return err
			}
		} else {
			fmt.Fprintf(os.Stderr, "Failed to create Directory `./pki`\n")
		}
	}
	return nil
}

func main() {
	flag.Parse()

	if bShowHelp != nil && *bShowHelp == true {
		showHelp()
		return
	}

	/** 初始化工程 **/
	if bInitProject != nil && *bInitProject == true {
		if err := initProject(); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
		}
		return
	}

	/** 签发证书 **/
	if bCreateCert != nil && *bCreateCert == true {
		if err := newCert(); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
		}
		return
	}

	showHelp()
}
