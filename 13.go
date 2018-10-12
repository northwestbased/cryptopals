package cryptopals

import "strings"

/*
ECB cut-and-paste

Write a k=v parsing routine, as if for a structured cookie. The routine should take:

foo=bar&baz=qux&zap=zazzle

... and produce:

{
  foo: 'bar',
  baz: 'qux',
  zap: 'zazzle'
}

(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given an email address. You should have something like:

profile_for("foo@bar.com")

... and it should produce:

{
  email: 'foo@bar.com',
  uid: 10,
  role: 'user'
}

... encoded as:

email=foo@bar.com&uid=10&role=user

Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:

    Encrypt the encoded user profile under the key; "provide" that to the "attacker".
    Decrypt the encoded user profile and parse it.

Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.
*/

func profileFor(email string) string {
	email = strings.Replace(email, "&", "", -1)
	email = strings.Replace(email, "=", "", -1)
	return "email=" + email + "&uid=10&role=user"
}

func initProfileEncryption() (func([]byte) []byte, func([]byte) bool) {
	key := Key(16)
	encrypt := func(profile []byte) []byte {
		profile = Pad(profile, 16)
		return AESInECBModeEncrypt(profile, key)
	}
	isAdmin := func(profile []byte) bool {
		decodedProfile := AESInECBModeDecrypt(profile, key)
		pairs := strings.Split(string(decodedProfile), "&")
		for _, p := range pairs {
			k := strings.Split(p, "=")
			if k[0] == "role" && k[1] == "admin" {
				return true
			}
		}
		return false
	}
	return encrypt, isAdmin
}

func createAdminProfile() bool {
	encrypt, isAdmin := initProfileEncryption()
	p := profileFor("aaaaaaaaaaaaa")
	a := encrypt([]byte(p))
	firstTwoBlocks := a[:32]
	adminBlock := encrypt([]byte(profileFor("aaaaaaaaaaadmin")))[16:32]
	payload := append(firstTwoBlocks, adminBlock...)
	return isAdmin(payload)
}
