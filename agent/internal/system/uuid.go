package system

import (
	"crypto/sha256"
	"fmt"
	"os"
	"runtime"
	"strings"
)

const (
	stateDir  = "/var/lib/rmmagent"
	stateFile = "/var/lib/rmmagent/agent_uuid"
)

// GetOrCreateHardwareUUID resolves the persistent hardware UUID or generates a deterministic fallback.
func GetOrCreateHardwareUUID(macs []string, hostname string) string {
	// 1. التحقق من وجود المعرف في التخزين المحلي الآمن
	if savedUUID := readCachedUUID(); savedUUID != "" {
		return savedUUID
	}

	// 2. محاولة استخراج معرف النظام الأصلي من النواة
	rawID := readSystemMachineID()

	// 3. إذا فشلت القراءة من النواة، اشتقاق بصمة قطعية من الماك واسم المضيف
	if rawID == "" {
		rawID = fmt.Sprintf("%s-%s", hostname, strings.Join(macs, "-"))
	}

	// 4. تشكيل UUID مطابق للمواصفات القياسية عبر تجزئة SHA-256
	generatedUUID := formatDeterministicUUID(rawID)

	// 5. تثبيت المعرف محلياً للاستخدام في الدورات القادمة
	persistUUID(generatedUUID)

	return generatedUUID
}

// readCachedUUID reads the persistent UUID from the local state file.
func readCachedUUID() string {
	data, err := os.ReadFile(stateFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// readSystemMachineID extracts kernel-level machine identifiers.
func readSystemMachineID() string {
	if runtime.GOOS == "linux" {
		// قراءة machine-id المولد عند تثبيت النظام
		if data, err := os.ReadFile("/etc/machine-id"); err == nil {
			return strings.TrimSpace(string(data))
		}
		// قراءة SMBIOS DMI Product UUID إن توفرت الصلاحية
		if data, err := os.ReadFile("/sys/class/dmi/id/product_uuid"); err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return ""
}

// formatDeterministicUUID converts raw hardware seeds into a valid RFC-4122 UUID layout.
func formatDeterministicUUID(seed string) string {
	hash := sha256.Sum256([]byte(seed))

	hash[6] = (hash[6] & 0x0f) | 0x40
	hash[8] = (hash[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		hash[0:4],
		hash[4:6],
		hash[6:8],
		hash[8:10],
		hash[10:16],
	)
}

// persistUUID writes the generated UUID to a root-restricted local path.
func persistUUID(uuidVal string) {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return
	}
	_ = os.WriteFile(stateFile, []byte(uuidVal), 0600)
}