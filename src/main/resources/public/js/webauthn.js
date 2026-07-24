
function init_webauthlib() {
    WebAuthnLib = new _WebAuthnLib(null);
    WebAuthnLib.init();
}

function _WebAuthnLib(param)
{
    function _init() {
        //alert($("#challenge_id").val());
    }

    function base64urlToBytes(base64url)
    {
        // Base64URL → Base64
        base64url = base64url.replace(/-/g, '+').replace(/_/g, '/');
        // Padding ergänzen
        const pad = base64url.length % 4;
        if (pad) base64url += '='.repeat(4 - pad);

        const binary = atob(base64url);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    function bytesToBase64url(buffer)
    {
        const bytes = new Uint8Array(buffer);
        let binary = "";
        for (let b of bytes) {
            binary += String.fromCharCode(b);
        }
        return btoa(binary)
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=+$/, "");
    }

    async function _register() {
        try {
            // 1. Challenge + Parameter vom Server holen
            const params = {
                displayname: document.getElementById("displayname").innerText.trim(),
                user: document.getElementById("user").innerText.trim(),
                rpid: document.getElementById("rpid").innerText.trim(),
                device: navigator.userAgent
            };
            const publicKey = await fetch("/phraselock-idp/webauthn/register/start", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(params)
            }).then(r => r.json());

            //alert(JSON.stringify(publicKey))

            publicKey.challenge = base64urlToBytes(publicKey.challenge);
            publicKey.user.id   = base64urlToBytes(publicKey.user.id);

            //alert(JSON.stringify(publicKey))

            const cred = await navigator.credentials.create( { publicKey:publicKey } );

            //alert(JSON.stringify(cred));

            // 4. Ergebnis in transportierbares JSON umwandeln
            const result = {
                id: cred.id,
                rawId: bytesToBase64url(cred.rawId),
                type: cred.type,
                response: {
                    attestationObject: bytesToBase64url(cred.response.attestationObject),
                    clientDataJSON: bytesToBase64url(cred.response.clientDataJSON)
                }
            };

            //alert("...und jetzt das Finish")
            // 5. An Server schicken
            const finish = await fetch("/phraselock-idp/webauthn/register/finish", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(result)
            });

            // 6. Ergebnis anzeigen
            document.getElementById("output").innerText = await finish.text();

        } catch (err) {
            console.error("Fehler bei WebAuthn:", err);
            alert("Fehler: " + err);
        }
    }

    async function _startLogin()
    {
        const resOptions = await fetch("/phraselock-idp/webauthn/login/options", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({})
        });

        const options = await resOptions.json();

        //alert("options:\n" + JSON.stringify(options));
        //return;

        // Challenge und andere Felder Base64URL → ArrayBuffer
        //options.challenge = base64urlToBuffert(options.challenge);
        options.challenge = base64urlToBytes(options.challenge);

        //alert("options:\n" + JSON.stringify(options));
        //return;

        const assertion = await navigator.credentials.get({
            publicKey: {
                challenge: options.challenge,
                rpId: options.rpId,
                timeout: options.timeout,
                userVerification: options.userVerification
            }
        });

        /* ...funktioniert nicht...
        const assertion = await navigator.credentials.get({
            publicKey: {
                challenge: options.challenge,
                rpId: options.rpId,
                timeout: options.timeout,
                userVerification: "discouraged",
                allowCredentials: [{
                    type: "public-key",
                    id: base64urlToBytes(options.credentialId),
                    transports: ["usb", "ble", "nfc", "internal"]
                }]
            }
        });
        */

        const resVerify = await fetch("/phraselock-idp/webauthn/login/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(assertion)
        });

        const verifyResult = await resVerify.json();

        if (verifyResult.success) {
            document.getElementById("output").innerText = "Login Successful";
        } else {
            document.getElementById("output").innerText = "Login Failed";
        }

    }


    this.init = _init;
    this.register = _register;
    this.startLogin = _startLogin;
}
