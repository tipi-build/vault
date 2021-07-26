# vault : reusable storage implementation

To build and run the test : 
```sh
nxxm . -t wasm-asmjs-cxx17 --test=all -v
```

Try in a browser 
```sh
nxxm run npm install --global http-server && nxxm run http-server .
```

And go on : [ http://127.0.0.1:8080/build/wasm-asmjs-cxx17/bin/ ]( http://127.0.0.1:8080/build/wasm-asmjs-cxx17/bin/ )

## Using from javascript
```js
let tipi = await TipiVault();

let vaultKey = new tipi.vault_access_key(this.passphrase);
let vaultData = new tipi.tipi_vault(vaultKey);

console.log("From nuxt : accessKey", vaultKey.encrypted_buffer); 
console.log("From nuxt : vault.encrypted_buffer ", vaultData.encrypted_buffer); 

vaultData.add({ user: "banana", pass: "password", endpoint: "https://github.com", type: tipi.endpoint_t.GITHUB});
vaultData.remove({ user: "banana", pass: "password", endpoint: "https://github.com", type: tipi.endpoint_t.GITHUB});

console.log("vault.encrypted_buffer ", vaultData.encrypted_buffer); 
```