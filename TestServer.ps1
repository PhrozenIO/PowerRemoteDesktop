# cd .\Projects\PowerRemoteDesktop\; IEX (Get-Content .\TestServer.ps1 -Raw -Encoding UTF8)

Write-Output "⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️"
Write-Output "⚠️ Only use this script for testing the application NOT in production ⚠️"
Write-Output "⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️"

Invoke-Expression -Command (Get-Content "PowerRemoteDesktop_Server\PowerRemoteDesktop_Server.psm1" -Raw)

$password = "Jade@123@Pwd"
$encodedCertificate = "MIIJeQIBAzCCCT8GCSqGSIb3DQEHAaCCCTAEggksMIIJKDCCA98GCSqGSIb3DQEHBqCCA9AwggPMAgEAMIIDxQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIHZPW4tq6a6ECAggAgIIDmCfxpSFuFdIf9B5cykOMvwPtM9AcpQldNOcSb1n4Ue0ehvjdE8lpoTK9Vfz1HFC7NeIgO8jSpwen7PJxQW85uXqe/7/1b6Q7eS2fJLJtNl2LMiPWEvyasJYmWW5h90Oh6T0IpD0uxWiEr0jfyDPbIWwUMmDgKi//IElxo+14z/ZGiSZuPdTiBclk1Xpsui6hnqFdPFqoZ2c4QftqormTYzeizNWbieuojuZnXoYzWjFTYKT5P4HpXylJNhLlHsJxFA88JsYcnmQg3U13eatEEmVY5DGoCtwtA7hl6CSdlnhVGhsOGh+Giri7WOJOV7cTrDcblA7EzL6yEPYvdo+yiLlPiDPOmqhC0DdCK2kwDJjcxCuiePImBke5vOJW+s9RBqKKzJQUj/2P1VTBGXgO6rWxFsh2je+7XtWtJoU1tTkH3fXH4VEiYX+is2qM+MY6WMSOLbVMzIpCJZMX4QnnR2s5mcfaovnblvv3e17Tcy/ouLEVyjRvEBnKpc3/6aACZdq83u1fryD8B2vP470lwxJEhE+aev3Pv2TBK9SdL+Xox/dWbkoc9Aqox+JK2/18tpjvKkG5ClTFdR6kfY384/WwQO4wiw0BQwCq/gG7Znkc7YKImqwobjxnD9Pq6AIyqiiAbSSA5emSbLcAo++cdbSdCwgwNksRHhzmR12nioSDq53Mqo82BltuU2PQcipBsdA00b3cD4AuVc+HIY/99gfsbKHJNLWwTX6qamUTl4dNOLCLbPIsIFrztzqGQ3cUgN5hN6fhVW5l8RLbx/s0R7pp+iO5DcLlg+kJiNBgstP+F2/bJrXKeqcron+0qJbM3o2oA5M95Za3DPVBDiW+xO0u5AxoEvk8ciQs11DS4hzOY/P7qJW1NNOa23/RMrlzt1fx3ARdSR/bGZ/jyMLdm32bT+mQ4aUCrERcKbg1vVEEeH9BG+/wKGOmBF/KJwT8e4EFFrH1Ur0Qmimhq2b2N6JaI2Fdasq4wwya3NVF3kax9vgBmO6JKfDQfy0HbRzWsCLJy8jCTUytkec0ZVmwBYEj5GubsV5knR6mqLPdIgf1gxlmmJfl9Gkzd/4bBSlt50uO10UwIO5fa1kPJXacHdzdt00RicoXycGx9HcIaY5jndV8volQmQ9WPFUTC3BL9uHQfSDxKpVn66eeATd8Ll4tp5ftakJkqXUMi9zQg7QqvvYS6dadEZcnTuCfDsBvpocutf09r4XUMIIFQQYJKoZIhvcNAQcBoIIFMgSCBS4wggUqMIIFJgYLKoZIhvcNAQwKAQKgggTuMIIE6jAcBgoqhkiG9w0BDAEDMA4ECD5W7MfyskhcAgIIAASCBMiRFTs6btm+b9m+7IcdlbVljAiIkIt+u8a8/odonMg9BXvYLw3VDkRnQ7j59S40N5S5B4L4J+FTxJW549ToOTb3gxseExRgUlX9tcb7pb6Odjp7JO+jOxRQ7f5P+AnFKVpHKs0P5z+NEp6OsANjs4h00vE5hKmAvh1N5fjGKlomps0OyIzqMCrK5jEQFGnrur4Z/3eAKH7GFKMVnWneyk/flPvjw03mcDbdY2tKlmaIKG13fqSl0gKB0Uv6lk1hLd/b7M9UC5Pqgv16Fhp0JmYC39FAtIRRZrhI8FXWDOa9TFVCS909B2jep6zIpLL1YqRY9XqYzcGLijOOr31ozFa+MGfIKoWjs0mD4B9MXtYcNy7cFJ25njbHs37+H8GUjGaUVPaR3+dkV3w/Y4z2DZRgF0XHSTFK62JqW/4ZHW6ZpnH+vdFuh+zRmV2hknfKdavxwRDYY22ebcO3YUhzVQ9gjfZHDgwp2IPb/p+Jqc6S2q+Px2MIt0H3a7uOtXm4BAANDPTS80n+nNvzp6OyaBECysjLlk1AEZtimj8+VslpHm0dm7Bl72oYh3cerBgBmFW0L2DEsU7RlnJGhva6eztNdAMngXOI2rNa2ZZdh72f3iceoTrpWCxXLggy0fN/Easm8jENSiaFKbU3wtvsIClqakSIcTD7/QF8eMQSaDy6Dgra4kwKccgl+dvMUAH9Ioeb1H3YDmnRmmm5xFtcXuL6eMj9UbLvJUoz500AMK48NVgTNJjhfkQx3KvoDZ6NwsPgK5i5VTTopw08H1iyJt+PzUDHMiHB69Zdyv6PSIGXlYw2EKt0KjxQ51bp5XgrRnGQ1uZDGRPCAZ7UsFDv09xAkOmRkOzGqbcmRoLaUmp0xJHjiCJRgbuyTPuF/6zM5Zyw3OtKfmD7+y+5oW/H0G1P3LfPrMbAtWlMv36mvKnunCQb/MtG7tyOwAP/XYvLe0LewhFnVRtvUP0ZaaL51YN6KynYHln3uK49aiwuNbidRP0HzHx6LsqaF8eVwLtXGJGoydBLZEkOUiQNUP6ohB3z3uh5HmeAhsgE+eXoL0YUG/WwtYKdqpclnOGeT17zjE1gZMAijTukERTPeFepRBkHgUXh+4T1iP7OU/Fv0jPGljYxFPjzBpfzjha4HlrBX8bg9TEMReMXvEPsZfrp4yfVT2nn2kI5mF57yUT2AyDKTXX3LaoT2Q//QltBiU1arDqfqd7I7FbvNRzB+c7bDn+nMGckfTgz0Oq4J1i2Vn9KDaQ+0GxWlxjH2HKp0/S1/AqK6dOzrK/OSXw5mxoIv7IUatt2GTfIDUwWfIAYvedMGg0IL/M0MKidOe2UviijKthogrUqLxVEb49bDnkFscZUXaSj7B+PYyQKBNtqiAf+pTZGCZwam+mVTiFPBvtMfGb8B8ZJWiTekRj6QPbw/lV+EJ6ubIAPs2rVt3z695Y8zURte6gh68wqbdBtnByIBUuU4fKRutc4EQuRYO3xe0kgNMbPMHKG4/Sy6TOVd9jI59qstcyJopZwPbUeWS6SDh2ogN3VIq9RA+GS4cmX2KrBZI1OtDCZMpBiO9Vk/08ZH/8G9bxYAfamhmL5DRazqvcnHxiYRn5B1FcNbUmlIfx5a5cAh2bDENkxJTAjBgkqhkiG9w0BCRUxFgQU6oiq2kAoZNGGRUL38qPEnlb0c7AwMTAhMAkGBSsOAwIaBQAEFFPUDCkjM9fUvXROzox5M48phvryBAhBDqmmQakSBQICCAA="
$pwdProtectedEncodedCertificate = "MIIRtQIBAzCCEXEGCSqGSIb3DQEHAaCCEWIEghFeMIIRWjCCCpsGCSqGSIb3DQEHAaCCCowEggqIMIIKhDCCCoAGCyqGSIb3DQEMCgECoIIJfjCCCXowHAYKKoZIhvcNAQwBAzAOBAgNh6FMllhTUAICB9AEgglY4Ui5DgOWz3oDZj9KShUgB67Xkws7NtRDtq6YBvpRZrgONNCU18/jjTKwbnpj5ih/BOjfWbfjwii49wfDekAN4x/54SuGweYEwywhDVDd9pF43F8WFDujDUelgSuAiH1gChVcxV3aO/0KijyLWr7TiJr3OLwKVXonLAc7IWRyJCsyi409BlsoiRS/PYavZSS6m6qifMH6WaiYut4VhOt1awMOe8VNeMKGRzi+Z5ib1ltYu5t65x42Hu1kyRWREZvIDIemfBqYo2jWjQQC7MrUkSg5PYwCmXHNhZxLzbyZb66sH3zBXhZoJIrq+pw+pCsp90VtmcIJsTwKblfc+lMCAlbNs75NKatlx2Ii/V1j7ktgEDCKAswOzPBDSsQY+OYfFRfbpcN6gkhE7MygNmigD/IM/mRt2t60ZF1sIka7+QQU4g0V1DAAusa5MqE6J4UJdwsQbO18jo+Vxx2G2YqNZztPPrqSF6/5lN8jjR6pWtbcH2//SQ18U0wy1TSPhDYt0b5qbfXUTwUWHjoHshw+7pHBeQiT32MSqSQjh8g2IHz3JGAMHH/jCiF1cCsyFUb/ok8c/i/8OmAJx6dXw3+UdknKHWF1FPQPIxnkAcSSIETvGzR6i9HUYVhR4Qug7wxj98gKRMEOcjA/u5juztFDo2KaCVc3v0OU84Kf1w3Xmt2lQxxb0eUr+aUs6SAxMI2NJt3I1aXDsKC+rmFGyP34TLmSu1MVZLO0YSDdIAIenaq0kAv81B5pkboDPtHGK/hPTcvwciC8kKOEaPcGjm3TIWyPbKt+xkZm/7GAkvXj0W41ZuGNsVdqt1eoxf0NUdiXGhn+FGhVOmrKu9jhJ6TJ9ErZVefBUsTxEHE+59iFKBdyggbIvf4BjIRThLuybdMafGAeqJvq5Sa3r9NawlgOQPE8sk6m43DKkP0cDbUT5H/xfdHaJ9YMzIf1VPZm/fYfFzerySv7IdkyWb1Q6X213cBufUJAw6QlKk64cV/aBAuLdmPKk1O2P123tgCr8haHiPkzqG3quuutfnxz78CLXc8q0sPYSUPyi7tuZJxxz1QHm0cOlciS4YDUNU/1DFMk+T0I6uhL8hQqvpG5gvNmcxsm4P6qbMepdyR2R0XqtjjOinrMtJaLFsV4ULjGI6+rDKr6anhA1MYFOYP6FoSC6xiN0J/4tBriDLeCqv8/xv1Ac/FCz67Rwaeka3aOTHyolJIC/Ukd2JjvMIGUvy0XeWBRGg+ZQkPA1qZP1dWZ79OwMQXGrg5jF56EKWaMEB8K2Uw9rUFi3VPcUm4v3dW3Givwi8TbO+zLYOFMELZHcmDrq1POrUmvfbtQKCKRZ7H0d+MZqDFefKVRoN6DyF0C7Vy3NUOVk+HyMHqD5NCbpbh67z1cIYjOv0SEo7YZ/wWyOmeqGfyNMfeWtYjmL4HY5t+QJw+Tip9zeCq2OZba2zpdS9hM+98vUI4uzePSoBLINJzukSt7aKAvRs6sd9WT05QUMFCG53wLBGMLgkZYlyi6ACIiC0SeZcEHmBAYZX3BO+IA3xiBzAEHQlFFX58zG7qV/fAfCmB1tIjC2IM8FgFyQvyuGz9ThBTBwDoY857yNmjq4/JtSGrakEgXnGHf+RimlOH9UZNBV+dh46aRer6cPqpdjqf/1UDRLBuLvBZ+v9sTlEk+/5kfIt9bnXYw/exs1vQ5KibrRCscYFlgYyMqzf6LjFAyneZqEZ0ZLapfWYG2J0BnMEYkvGgkts4/0SFncK/PjctQEB88G28XyzW2u157ARXrY6Yi+cYZWUT14Da2pzjPZx+2bxxXl6v5TxYKBBQeVR8u6M5DGdT+iWb3GKEJglij2mJDxJK+wHrSzy1CE8PFniKhrIQfHoBdRddJ9sh7m4rZd5AE7RdsCTww46dXKIyCdmGYR5HPsSfMIQGGZSU4bisOp0W3V5xbVeR4l/oBeSz/tGMD2KN2zZWwa1eCgMcWftdYPgM4Dl+FUz3QZUlV9q6VH7NiXBQR5hJa1595kqZyFnRDuKHOy+TUfWP+GtjV3H0GXWh+1S+Lbs1BgclMaxpfpd9vEiLR0seSgDuSOCyjuruWtXjzgvGeK9tCF8JHpbctDWve+Wvij8q5euqyPbUGsAbj13CYKg5TqSJUBvSw2tKjBj34QFSLZjMPgWQkO6swxVVtQ/VQ3JllHKNj2IKfgfs1FVbQmUllI9Gb3SpUiQRTmOT+Yxo1xxhvJvrMlLjBtpcdiaOXZvO0x/T8QBUYJpp6KLN+ueYdt0P4fULzqNzL11ro9Li0GSBAmS3ALodXwh++MTUcbPDALF5MF/joiTtwAGQwWymb/3ck7T5rMgtANVIYx3CFPnwuVZ5a6/8UVZ6opcc99+gMNP0HTy8NoxObDpRj+6gvJY70plO04rAy5nwKdrPKxDN7UGjO2CmM4mifcB3HwkFZkJ4Ta0L5BMiAeI0UEkzjmXk1A+BOggVvU0cWjfKQ7hMEhowHC9EeCgSo+biNqbWHg/aWf4nxA4/lOJmDJEAYDd2dRQwhb3S1Ylf4jVSOu6UC+6AOy4OOQgQi45RTWFouU+T9EdK1qsH6oSAl0i97VzBDju1kEJxASKCQTDx86YnB0tj3WjsP7BUknCmF1F8iXEpGnc6GIoC/wCATPMSlFm4JS5D+IYV2EuHMrI2zsGjpSIRjkUoYtdenKuFPFQAHho/+R11hgHIfT5lAbd5Jj0LZUoYhnsgMSOJQVNNNAYkh6+YTMR5OM15t/fz/Q75whdUEXkevb+hYIE8LAbDjLKsIt+/+6k7O0q1XdScxxFHsUkYYLcmbG5YYsVQE9wFxG9SJgEzFe56lX17rSWj5TwwPKaI8JQCRi99/hkC4sHUwyeeyrb3QGu+sV9FxkhUWPovaP9JPnp2JnacXyHAFUdCuZbuKAr5gzYpbSairaWRDwRWVkig/DFQfjjVCdur/CsC8iw4Js5zNvOTs+bQ8H61+cmP+AOGiK6liqmtvtWP2DC2pgS1/Zt0eXPNaZOsUtnl5dndpO4GbuZNqAdiicsC6t4AVjlizqubg3dX7Uu0od8iODKVKSbE3SIXZ+1tPhB8GadTZvnRTRSayXhGCEMfXmbv1I9jBjR73e0uWDF0qHE4zgyt8MKTLecxFmpBTvCTz6MNMChvOlqFWGnauHxomS0MZw9dLpcvf/JWngbIns4nRRzGB7jANBgkrBgEEAYI3EQIxADATBgkqhkiG9w0BCRUxBgQEAQAAADBdBgkqhkiG9w0BCRQxUB5OAHQAcAAtADgAZQBjADIAMABlAGUAZQAtADUAYwA5ADQALQA0ADEAZgBhAC0AYgBkADgAZQAtAGEAMwBjAGIAZAAwADIAMQBiADYAOQBiMGkGCSsGAQQBgjcRATFcHloATQBpAGMAcgBvAHMAbwBmAHQAIABSAFMAQQAgAFMAQwBoAGEAbgBuAGUAbAAgAEMAcgB5AHAAdABvAGcAcgBhAHAAaABpAGMAIABQAHIAbwB2AGkAZABlAHIwgga3BgkqhkiG9w0BBwagggaoMIIGpAIBADCCBp0GCSqGSIb3DQEHATAcBgoqhkiG9w0BDAEDMA4ECHdcpMitRWaGAgIH0ICCBnBo3WaSHRFPbHPskLA3tFKjFosqUV4K5k/abpG737dhmiQ/iFFremexUru09lwy1PqlUX55RZXR1SpNrKSQA5Ummm4uWhCk+ObwCUsNzerOnDValn1Q62RAJApZsD6ZHJjNl4ZN2SPxOxw3V8fwKGLZKLjHkivXictApYIglL5SUX5kc0bioPXfKQM89dpgzOyuOGR8AdvXY8MrYNeQW/31Hc6WYAgSlSE8gOi/OB2iRM35JKSFM5mtsAj9dz/kVl/UWKKcW19FWagfXn4c6Q6Sw09YqwI+enzmd2zxnAMk2E5OljpaLHcms59y6gOY/eRT6jt0X81YPkI6dVDP01Ea1SyMyCoBq0lONTkkf4MkxhQR3kY6J2S2UeqB5k9Y8dSevMaILJOIdUdh9xs1EJqEH1OS32zE+f9nznDtXEqQELOsAYlHMfdCE7XHqPzcfvSeYJ5b8xfsr75QENHvI4sV4QepXsVjqzCLSalEjswo1W6AEIJfMg6QD8DvI4HLAtWrk9osIeoaD35HTlsFmKKyM1Z/mWHjc5v3xS0wpRI9g9rdeolNR3pssb7DxDZVgANtzkPbceBTgVYbUmzHht8c1TOaX13UsldJfOKyr8WWcoQwhlJGcs8X0XRxPLNnwjhMnP4Q1UoGZSwE1Xt7ZP6Wr96xJduMdY/meoqToTbYL4TsPEsoupB2UZiTZe/ZQySK4EPFDdl3E2V8kDUzoAdzbP/kbleCWCPHDrxw2yKPz6rOFO1fStRxQ4BqEmfQKsmcmlmLiGpO9Y3SeAzFEmHTHYNHWC/I+rzvVVKmjnaD6Z6FanTPpiL7c1JLS+m1Leui/lS2QOdMgut6aV/T3kPZJwBGY0A+mV6usTDy3Tpr62SCWW/HyUPCq4vWMGuBLWmJOCNrYLPwDzv2+hnb0q82FywknGntc96sjAdxknvKy66ZhaA4E6uIr7h/RkSCAbxxl4+sBFv5If4HYO4Pcc5OtFvx6HRm27HMgD2HnGQdCpq7e2Lbi9KQyc7Yrcl2K1CwTnpcFHFe7Mt/XcvvDZ+g4Jz0rMEL53lgclTMhB9b9sXV2uGxtx/LPD9CyoTqZrjHlKqB2U36U6rG/i9nTZFecnr66ZWTREVZlyc7I1/GPbYVZMXpo2q6JUtm1UyaVYhNlw1la571LMjLzJXePwySZGdpe4OL12DZcFgv1jqv1ePWiX9W/Hdyxdoh0kkyDxgpwBw5ieU0smv4r7NBsKXqDwHA4BzjroaV6Pj1UHQ8B964d6IacZ2oHOUkfCfIt/C4ODaCmNm/55grD/Q4buvjfHrQdf4ogcP2a0WTeGYHJmJh4QbEImUMvq9CttrXktjBTVc7M8RiWNER0JW61H4DOow8lnlZsHZbGWP5Ux7BAyDvl3dajU4+t8Icb7ESClUiiwEhlV+Yu7gbWCOHMUi1zSUTMf1PIZmXvxz2OofugRT7m1OjLKN090eQdTzAIuDPx3yS8wEJHmdBVtpI+joWeumwff85w7M3D6vLpL7FEGRiTID2Qnq42U66F1WGMTlgOdQ10UHVAsJlKOF2GOYhtqfjUde5vDsTAg+EX6RGSmXg2k27V2XEBUGVSHCeeB6/LGgCfN6TJOPbG2Xqhf6Nc/YlnnfbRMUg72Mkpy+s27YkKBytmqwbbe8/VEtqtIFLFT+O7JAtLvarhInS0X9HBrsjIR8zltDg3M4IKhGrdmt4kIH0wAjM0q+4uQo28fARyzLZjSG1q3SE5D6uN5NCOxYzA/jzqY8jPEhi0t71hNdWFWxLpwuI2Z+zHuzPDDm152OsXpeRMtX3mawo2Vh7l3oWWuvlHnq5xZ2gmD47Hb9TktRvoAfACBX0lVn/BVn/mKO64emorRlP9+b8OJTtwd9M8U8mNvWTLvl/5BSGINI2RnL5hpPAwqOHweZZOrN+Cpw7GTzsOdKwNapLrPgHFZAKwLkt0Z2uQFNmbgLid018wHoBE01QRrGwDYU8HwEyBNXrNrtRnKni38K0hey/5oNpvfR1XYldTD6zsLceFxgMglAVSQ6DSkk1pBbWQkXdaXQZGzfRUdvtEYX9XPWjjwQEa99gINV/QSrJGSkuWYzZTKyUokTlL9Zr++EgohQaChY9sJOyBPn9YmgqimHAv2r8KBVV7/41pkJKtGze+VWbXEdedCxBhojeL1ek9iHIr4KwUolvzgfCo6y/pW5cMDswHzAHBgUrDgMCGgQU2Wo42CJgVUdtGF2LPp+bG5Txd68EFLH8icX7902y7cMKDQwEswHHq4hbAgIH0A=="

Write-Host "Scenarios"
Write-Host "---------------"
Write-Host "1. Classic (Secure Password)"
Write-Host "2. Classic (Plain-text password)"
Write-Host "3. Classic Default Certificate"
Write-Host "4. TLS v1.3"
Write-Host "5. Verbosity Disabled, View Only, Prevent computer to sleep"
Write-Host "6. Receive clipboard only"
Write-Host "7. Send clipboard only"
Write-Host "8. Clipboard synchronization disabled"

Write-Host ""

[int]$scenario = Read-Host "Please choose scenario (default: 1)"

switch ($scenario)
{
    2 
    { 
        Invoke-RemoteDesktopServer -Password $password -EncodedCertificate $pwdProtectedEncodedCertificate -CertificatePassword (ConvertTo-SecureString -String "hello" -AsPlainText -Force)
    } 

    3 
    {
        Invoke-RemoteDesktopServer -Password $password
    }

    4 
    {
        Write-Host "⚡Check that TLSv1.3 is working."
        Write-Host "⚡Check that certificate file is correctly loaded and used."

        Invoke-RemoteDesktopServer -Password $password -CertificateFile "c:\temp\phrozen-pwd.pfx" -UseTLSv1_3 -CertificatePassword (ConvertTo-SecureString -String "hello" -AsPlainText -Force)
    }

    5 
    {
        Write-Host "⚡Check that verbosity is disabled."
        Write-Host "⚡Check that remote viewer can't control mouse and keyboard."
        Write-Host "⚡Check that computer wont go to sleep."

        Invoke-RemoteDesktopServer -Password $password -CertificateFile "c:\temp\phrozen.p12" -DisableVerbosity -ViewOnly -PreventComputerToSleep
    }

    6 
    {
        Write-Host "⚡Check if server is only authorized to receive remote clipboard."

        Invoke-RemoteDesktopServer -Password $password -EncodedCertificate $encodedCertificate -Clipboard "Receive"
    }

    7 
    {
        Write-Host "⚡Check if server is only authorized to send local clipboard."

        Invoke-RemoteDesktopServer -Password $password -EncodedCertificate $encodedCertificate -Clipboard "Send"
    }

    8 
    {
        Write-Host "⚡Check if clipboard synchronization is completely disabled."

        Invoke-RemoteDesktopServer -Password $password -EncodedCertificate $encodedCertificate -Clipboard "Disabled"
    }

    default 
    { 
        Invoke-RemoteDesktopServer -SecurePassword (ConvertTo-SecureString -String $password -AsPlainText -Force) -EncodedCertificate $encodedCertificate
    }
} 