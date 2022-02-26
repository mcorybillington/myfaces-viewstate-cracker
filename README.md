# myfaces-viewstate-cracker
Script to crack encrypted Apache MyFaces viewstate object HMACs and retrieve the key.

This is obviously targeted towards and someone using the same pretty weak key for `o.a.m.MAC_SECRET` and `o.a.m.SECRET`. If it cracks and the same key is in use for both, you can use the script in the writeup listed under [credit](#credit) to encrypt your own payload.

Usage for HMAC cracker:
```
usage: viewstate-cracker.py [-h] [-q [QUEUE_SIZE]] -w WORDLIST [-a ALGORITHM] (-f VIEWSTATE_FILE | -V VIEWSTATE)

Viewstate encryption key cracker by M. Cory Billington.

optional arguments:
  -h, --help            show this help message and exit
  -q [QUEUE_SIZE], --queue-size [QUEUE_SIZE]
                        Size of queue. read the docs. idk...
  -w WORDLIST, --wordlist WORDLIST
                        Path to wordlist.
  -a ALGORITHM, --algorithm ALGORITHM
                        HMAC algorithm (sha1 or sha256)
  -f VIEWSTATE_FILE, --viewstate-file VIEWSTATE_FILE
                        Path to base64 encoded viewstate.
  -V VIEWSTATE, --viewstate VIEWSTATE
                        Viewstate as a base64 encoded string.
```
Usage for viewstate decrypter:
```
usage: viewstate-decrypter.py [-h] [-q [QUEUE_SIZE]] -w WORDLIST [-a ALGORITHM] [-o OUTFILE] (-f VIEWSTATE_FILE | -V VIEWSTATE)

Viewstate encryption key cracker by M. Cory Billington.

optional arguments:
  -h, --help            show this help message and exit
  -q [QUEUE_SIZE], --queue-size [QUEUE_SIZE]
                        Size of queue. read the docs. idk...
  -w WORDLIST, --wordlist WORDLIST
                        Path to wordlist.
  -a ALGORITHM, --algorithm ALGORITHM
                        HMAC algorithm (sha1 or sha256)
  -o OUTFILE, --outfile OUTFILE
                        File to write decrypted viewstate object
  -f VIEWSTATE_FILE, --viewstate-file VIEWSTATE_FILE
                        Path to base64 encoded viewstate.
  -V VIEWSTATE, --viewstate VIEWSTATE
                        Viewstate as a base64 encoded string.
```
Example usage for HMAC cracker:
```
$ python3 decrypt_viewstate.py --wordlist wordlist.txt --viewstate-file arkham-viewstate.txt 
[*] SHA256 of viewstate/HMAC:  ac8ccc9d3d76e77271ffbdc72e0e57485573423675641ac50d49d4e00d869406
[*] SHA256 of viewstate:       fcd63919c021962f94cfd1cca36c0f787b56aaab3547681cfa67b7ad217ce8a3
[*] Original HMAC SHA1 digest: 9d15ffad383b3f1329f6118d29037f925afe5f27
[*] Running...

[+] Key found: JsF9876-

$ python3 viewstate-cracker.py -q 100 --w wordlist.txt -f viewstate.b64

$ python3 decrypt_viewstate.py --wordlist xato-net-10-million-passwords-1000000.txt --viewstate 'o4swGdxTZXw1mKtPxFkjUuWrKOBMVnhQ7RbMizpCb4xVYti30eaLecyiLLU7plNhjPFRnShy4IlIzxo0JHimBY3Uq1igjemgy0Ki4udfDHCBAJC2Yt%2BEq3hlEwGdEWrah3tqcdo5Gxzenm%2BTobetH0%2BaG8%2BiCEB1RbCm7b%2FRwuOINGcnD%2BFO3DfRKu9gMF%2Bhys2vYzpsGEyHK3knl7tEaywlBVCuHcXMqHLkcdxxT%2FxmSmtDFG85aQTVagEZSOEEX9bCEH73rYHKIdkiMmo3tRSv0aFcuTCzo9ywZEOE7bULbrBQyiDX34vkaoTgGwZx5xiJxcuYu0CBGPZRDq1UBGH1QEaZ391dmKFPiBhIqgml%2FErcnLpXhN2CNsbBu9HHKSuy0lTdaYJifqCf5zOXppnKQiTkInD9AN%2BIjrIKoKhLslblPlDOJTrY6IWKCYEH9ZL8tl0EWKQbiDEBanGkxqkFjjIIqXZFoV%2BTjkS1FnVO%2FoHWBB6y1rXJo3U1C5yWD2YmTWm4GDisEHwUAFbDTHvZSVfjA0tLKeDOxOM%2F8vhiJvs7XB%2FiL0xioZBCDhyyogM5ilMzKrxi25pKdV7qKFYgBIpi82HZJBiyt0w%2FfqlS6hjo07yHrHeKgVe5KiMmPRtt6h4buRWMlkPun2jgm259cO2loSVMSxjNu9%2FCCnMkGLK3TD9%2BqV2YP5mtCOlGyIG92TCIcaFw8tZsfH14qFQuvLXlje%2BWBoE1cgT2Ozo%2Bus8jmf0nBttP8g%2FGkIl6LoObMsC3BpXUjNHX%2Fl6ZpFrpHPYqF04R1vdMLtxFTMVOrQbaoakmK3uiTmx6KyVVK59aLaXuOysuH%2BsV3gx3v3PoFcpnc1%2BAJTHWKqHfCy1opEh7cDv2tdwg%2FTiZmJ7Y2965FPpV2Dw1mICArOvAOCf9fzZiZncI%2BCoX%2FOuaRilAYhWNKe8XzdQP6NjTNMEAoU8qpv%2FvNvILq22We0wQ1mUW3OrpauOZzU7%2BmQoL%2BGnNtOpmFx%2FzHz9CO1Qw3PfdQHYhQvw4tg%2FW90wu3EVMxVnQ5zD2tQV6GrCAJFCMnfi8x%2Bf6%2BnW9kb%2F3KJjeLP9EaVtnw4HgbxOvCM237bf506YkZewPgxQiLewUhIRMklMJnDnzAWGDt7FI7YRaUwB8JGXyetfsWfwktvElTU8G%2Fq7MLUp4%2BGPRDBvo6SMhFsfpnWDv02QaeNaSLMlE9boIJFbYlwyeLs9OWTCIP4cwrVmtcdeHaJalFuas%2BcLlmoyCpiYNGomoF2fGsKSBlO02H5aD7eIK4KEmO7jZE%2FsAoHMWWJfxo23t44S4ahSOeHfvlzJqhV2WT62diMizXDhDlWLlH5eRWvOufroUtk3jPS%2B%2F%2B6Ud4Bajai2yaRfDxHbTJgZ6IWsFXJmYIJXEh5ODaSShdwisWrLMFqobrL%2B3iOMkCTIPHpwTC4k4WjyVGoC3EmsS4trV68wenfb4asCPSZABGwnwfoqx6CHK%2BPGB13aRjo4KzHOVh7W5RxqOnjWWACJFXGhBny4XW4CootugK59aLaXuOyv6AM6KeF8cfH0GU8FiZ%2BF0wy6hHdRzv29OOgXpgJZaMjXVY9Qh34X7raWi1V1bOk3wI5mPW2oCG%2FHiPH0hgDaLJD%2F5rWumATBRhPfQdMukPUuvh7aBrYKhTjoF6YCWWjI11WPUId%2BF%2B62lotVdWzpNlg7XO%2BO71UXIulcb15uC4Uo%2FmVX%2BF55hhstnKpruvCRn1%2FE2U%2BSHSUwJwYQalMFkB3EYe3Bg0twUHB0FLdRlgk%2B1LfoOx%2BOAGABHbKLruPQnSgSaOr0QO7fs3ABDYpM%2B0brsRYoVq%2FxZrXHXh2iWpRbmrPnC5ZqMgqYmDRqJqBegTWtulqHIbfmX3cwmZtK73nCNfCh4bR8nU8ph%2B9dFQFQm3TB92LYOU%2Bo9ImRGT5ZxHsqO7r9vsYEY9lEOrVQEonBeV1772fxzAWY30P6lQjx7QKzqFpGw7VVu9x6xj4HqyzMw3srhBWpB1evb%2F2cj2VJfV2Ik%2Fe1XeDhxd98FCKdtuwD%2FhfhKKwyMHBLd%2B%2BTRSti5%2BPjgedH8VrYCDw%2Bh7TXbFuuzmic0Ejp%2FMdRQ2lgM7A1Zk2tN7LvOGYXm5vai2%2Fp9KNzcb82%2BWwUxFUNdG%2Fr%2B91Skv9JVChFgo1kBKZ5DSG9GVW0c93lwaDPZR8m2MdKuCGEIGysMjBwS3fvkWX6kL5w8G98g8evxDbfYkHzyF14jnr2kMvA1HZRyD2wcvsnF03HnathuuAfsXFi9nSS%2FwbSz1fz4k0TLI7Jwpbv6aAGFYU9IId4BaMaICpD4zmUdsKF%2FchdWUs7E65By387U2Ejeqn%2FY3UAanW9XVGnW1aWk9nG1iLSIviO15BJYS2423DKh2itxBdEkoL7a2k0YgPMLX%2BTweGj5FUR%2FlCPgQijAFFrHWRvjlEtsVNbr09Qek%2F0QE3yWXS1W%2FgaT%2B7VnbdN2xAhE%2B9N5PSzJudEi8q%2Fo29VPSGioyPZd%2FiNpmNoUDeaeXEVrvY0L%2FaRMkBoThhoybIwKm9JRORG5quVg7mI39K3ANZaw6BBLyJDVbXmOcpydaV%2BJ4ehZuDU5EJNCdYdlqpK5IUgV5VNtTWO9f9YgPaneg14o%2B53eYRjgAQvWxmK%2FVII6JP9zUlbTzD60JeAbleovB8fLJf0D3aUv3mla%2B%2FLyWEXo2NfiqjFqPb9b4NHR199UdBVp6X2nev37%2Ftu0vBXvZz%2Bls4886hDPhV3RdASjsJaoZPrEReF8f43oev%2Bx6ZHIUdkCdk5uThniTrXeAWImx1USbtujkG0xSYdfK%2Fs8Az9gV7hyTmqI0ewkaYsX9uSA%2F9wVoArXnRX%2FrTg7PxMp9hGNKQN%2Fklr%2BXyc%3D'
[*] SHA256 of viewstate/HMAC:  ac8ccc9d3d76e77271ffbdc72e0e57485573423675641ac50d49d4e00d869406
[*] SHA256 of viewstate:       fcd63919c021962f94cfd1cca36c0f787b56aaab3547681cfa67b7ad217ce8a3
[*] Original HMAC SHA1 digest: 9d15ffad383b3f1329f6118d29037f925afe5f27
[*] Running...

[+] Key found: JsF9876-
```
### Credit
I really just worked backwards from this [Hack The Box](https://www.hackthebox.com/) writeup from @0xRick:
- https://0xrick.github.io/hack-the-box/arkham/
