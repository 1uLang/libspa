package iptables

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

const spa_cluster_prefix = "spa-pass:"

// OpenAddrPort 开放指定IP及端口
func OpenAddrPort(addr, proto string, port, timeout int) error {
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil
	}
	cluster := fmt.Sprintf("%s%s%d", spa_cluster_prefix, proto, port)
	//判断集群是否存在
	cmd := exec.Command("ipset", "list", cluster)
	_, err := cmd.Output()
	if err == nil { //存在 则直接添加
		goto ADD
	}
	//2.创建集合
	cmd = exec.Command("ipset", "create", cluster, "hash:ip", "timeout", strconv.Itoa(timeout))
	_, err = cmd.Output()
	if err != nil {
		fmt.Println("do cmd : ", cmd, " error : ", err)
		return err
	}

ADD:
	ShieldIPAdd(cluster, addr, strconv.Itoa(timeout))
	//屏蔽生效
	rid := getRuleId(cluster)
	if rid == 0 { //未添加该规则
		cmd = exec.Command("bash", "-c", fmt.Sprintf("iptables -I INPUT -m set --match-set %s src -p %s --dport %d --j ACCEPT", cluster, proto, port))
		_, err = cmd.Output()
		if err != nil {
			fmt.Println("do cmd : ", cmd, " error : ", err)
			return err
		}
	}
	return nil
}

// ShieldIPAdd 新增ip至ipset中
func ShieldIPAdd(name, ip, timeout string) (err error) {

	//com := exec.Command("ipset", "-exist add", name, ip, "timeout", timeout)
	com := exec.Command("bash", "-c", fmt.Sprintf("ipset -exist add %s %s timeout %s", name, ip, timeout))
	_, err = com.Output()
	if err != nil {
		fmt.Println("do cmd : ", com, " error : ", err)
		return
	}

	return nil
}
func getRuleId(name string) int {

	ps := exec.Command("iptables", "-L", "-n", "--line-number")
	grep := exec.Command("grep", name)

	r, w := io.Pipe() // 创建一个管道

	ps.Stdout = w  // ps向管道的一端写
	grep.Stdin = r // grep从管道的一端读

	var buffer bytes.Buffer
	grep.Stdout = &buffer

	_ = ps.Start()
	_ = grep.Start()

	_ = ps.Wait()
	_ = w.Close()
	_ = grep.Wait()
	_ = r.Close()
	res := strings.Split(buffer.String(), " ")[0]

	rid, _ := strconv.Atoi(res)
	return rid
}
