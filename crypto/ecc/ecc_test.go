package ecc

import (
	json2 "encoding/json"
	"log"
	"testing"
)

func TestExportAndImportKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	// Export public key and private key to PEM
	privateKeyPEM, err := ExportPrivateKeyToPEM(key.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	publicKeyPEM, err := ExportPublicKeyToPEM(key.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(publicKeyPEM)
	log.Println(privateKeyPEM)

	// Import public key and private key from PEM
	privateKey, err := ImportPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		log.Fatal(err)
	}

	publicKey, err := ImportPublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		log.Fatal(err)
	}

	if privateKey.Equal(key.PrivateKey) && publicKey.Equal(key.PublicKey) {
		log.Println("OK")
	} else {
		log.Fatal("FAILED")
	}
}

func TestEncrypt(t *testing.T) {
	publicKeyPEM := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEE12FoNP1B5eLiUSMKAXz3aTUmcVN
9NdxkXMtD2gSLmGWfXAkTKaU7eL+eVt/InsLYF9lGf2/7mw1ZxRvTMEh5g==
-----END PUBLIC KEY-----
`

	publicKey, err := ImportPublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		log.Fatal(err)
	}

	// Example message
	message := []byte("中央氣象署表示，今天（12日）持續受東北季風影響，再加上位於南海的桔梗颱風外圍雲系，桃園以北、東半部地區、恆春半島及中南部山區有局部短暫陣雨，明天天氣如何？氣象署指出，明天（13日） 清晨東北季風加上第23號颱風桔梗外圍雲系影響，台灣附近水氣偏多，北台灣及東半側雨時長、雨區廣；目前太平洋地區有四個颱風，包括輕度颱風桔梗、輕度颱風天兔、輕度颱風萬宜、輕度颱風銀杏。目前太平洋地區有四個颱風，包括輕度颱風桔梗、輕度颱風天兔、輕度颱風萬宜、輕度颱風銀杏。原位於關島西方海面的熱帶性低氣壓，今天凌晨2時已增強為第25號颱風「天兔」，持續朝西北西方向前進，預計周四將來到呂宋島東方海面，之後路徑分歧度大，請留意最新預報資訊；關島東方海面的第24號颱風「萬宜」，未來向西移動，對本周台灣的天氣沒有影響，後續動向持續觀察中；第23號輕度颱風「桔梗」，今天將進入東沙島海面，之後朝廣東海面前進，直接影響台灣機率低，不過其外圍雲系會讓台灣附近水氣增多，迎風面留意大雨或豪雨；第22號颱風「銀杏」，即將減弱為熱帶性低氣壓。東北季風影響，易有短延時強降雨，今日宜蘭縣有局部大雨或豪雨，基隆北海岸及及台北、新北山區有局部大雨發生的機率，低窪地區慎防淹水，山區慎防坍方及落石。今日東半部、南部沿海及恆春半島、綠島、蘭嶼易有長浪發生的機率，屏東（小琉球）已觀測到1.5至2米的浪高，請注意。今天（12日）持續受東北季風影響，再加上位於南海的桔梗颱風外圍雲系，桃園以北、東半部地區、恆春半島及中南部山區有局部短暫陣雨，其中基隆北海岸、宜蘭地區及大台北山區雨勢較為明顯，有局部大雨或豪雨發生的機率，花蓮山區也可能出現局部大雨，其他地區雲量增加，也偶有零星降雨；早晚天氣偏涼，台灣各地低溫約22到24度，白天北部、東北部、東部舒適到稍有涼意，高溫25至27度，其他地區28、29度左右。氣象署在臉書預報，明天、周五、周六水氣偏多，請民眾留意後期熱帶系統動向。明天（13日） 清晨東北季風加上第23號颱風外圍雲系影響，台灣附近水氣偏多，北台灣及東半側雨時長、雨區廣，有局部短暫陣雨，基隆北海岸、東北部地區及大台北山區有局部大雨或豪雨發生的機率，東部山區亦有局部大雨發生的機率，其他地區為多雲偶飄雨；白天起東北季風減弱，降雨減少，北台灣氣溫回升，桃園以北、東半部地區及恆春半島仍有局部短暫雨，西半部山區也有零星短暫雨，其他地區為多雲。北部、東北部、花蓮23～28度、台東24～29度、中南部23～31度。周四（14日）環境轉偏東風，水氣更少，各地大多為多雲到晴，東半部地區及恆春半島有局部短暫雨，北部山區有零星短暫雨。北部22～30度、東半部23～29度、中南部23～31度。周五、周六（15日、16日）颱風外圍雲系影響，北部、東半部地區及恆春半島有局部短暫陣雨，南部地區及中部山區有零星短暫陣雨，其他地區為多雲。北部22～29度、東半部23～28度，中南部23～30度。周日（17日）東北季風增強，下周一（18日）東北季風影響，北部及東北部天氣轉涼，其他地區早晚亦涼；桃園以北、東半部地區及恆春半島有局部短暫雨，其他地區為多雲到晴。北部、東北部22～27度、花蓮、台東23～29度、中南部23～31度。下周二、下周三（19日、20日）東北季風影響，北部及東北部天氣較涼，其他地區早晚亦涼，北部及東半部地區有局部短暫雨，其他地區為多雲到晴，下周四（21日）東北季風逐漸減弱，南方水氣北移，北部及東半部地區有局部短暫雨，中南部山區有零星短暫雨，其他地區為多雲。󠀠撰稿：吳怡萱")

	// Encrypt message
	encrypted, err := Encrypt(publicKey, message)
	if err != nil {
		log.Fatal(err)
	}

	bytes, err := json2.Marshal(encrypted)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(string(bytes))
}

func TestDecrypt(t *testing.T) {
	privateKeyPEM := `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIK+2b7h2oemDHiLTVX2DdjgG9SJYjvT3WqjlWtFbnI/PoAoGCCqGSM49
AwEHoUQDQgAEE12FoNP1B5eLiUSMKAXz3aTUmcVN9NdxkXMtD2gSLmGWfXAkTKaU
7eL+eVt/InsLYF9lGf2/7mw1ZxRvTMEh5g==
-----END EC PRIVATE KEY-----
`

	privateKey, err := ImportPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		log.Fatal(err)
	}

	bytes := []byte("{\"EphemeralPublicKey\":\"BPW6HCrmAdAUjN+tKbGeMQEaTMTYBbDcUxtPmHS7UXCSwL6HSkT6xMuaQ9jrrL+SwjLKeWzwp5MMDBQx5M1+qmI=\",\"EncryptedData\":\"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\",\"Nonce\":\"QAsovLYqQTwutSVL\",\"MAC\":\"tRY5fvaKx15JRk3QGfN3tePSMdPn+NLlJp9VkE0A32Y=\"}")
	var encrypted EncryptedMessage
	err = json2.Unmarshal(bytes, &encrypted)
	if err != nil {
		log.Fatal(err)
	}

	decrypted, err := Decrypt(privateKey, &encrypted)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(string(decrypted))
}
