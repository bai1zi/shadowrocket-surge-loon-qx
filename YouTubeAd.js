#!name=youtube（改）
#!desc= 测试
#作者小白脸佬

[Rule]
URL-REGEX,googlevideo\.com\/.+&oad,REJECT-TINYGIF
URL-REGEX,^https:\/\/youtubei\.googleapis\.com\/youtubei\/v1\/player\/ad_break\?key,REJECT-TINYGIF



[Script]
/油管 = type=http-request,pattern=googlevideo\.com\/.+ctier=L,requires-body=0,script-path= https://raw.githubusercontent.com/bai1zi/shadowrocket-surge-loon-qx/main/YouTubeAd.js



[MITM]
hostname = %APPEND% r*.googlevideo.com,youtubei.googleapis.com




#*****
$done({ response: {status: 408} });
