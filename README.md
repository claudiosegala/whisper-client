# Whisper Client
Defines a script and a library to be used when initializing a client app that communicates with Hydra's OAuth endpoints and Whisper.

# Life cycle and params

This script/lib takes care of creating the Hydra client in case it does not exist.

Given that, when firing up your client app, you'll need to provide a `client-id`, a `client-secret` and Hydra's endpoints `hydra-admin-url` and `hydra-public-url`. 

The scopes that your application is able to ask for when issuing tokens are set via the `scopes` variable.

You can also define the level of event logging by setting the variable `log-level`.

After making sure the client exists in the Hydra instance, this utility starts a client_credentials flow and emits a new Access Token.

# Use as a lib

The following code should get you started:

```
import (
    whisperClient "github.com/abilioesteves/whisper-client/client"
)

...

whisperClient.InitFromParams("http://localhost:4445", "http://localhost:4444", "client", "password", []string{"client-specific-stuff-01 client-specific-stuff-02 "})

t, err := whisperClient.CheckCredentials()

if err == nil {
    tokenString, err = whisperClient.GetTokenASJSONStr(t)
    ...
}

...
```

# Use as a CLI utility

The following command should get you started:

```
./whisper-client --client-id teste --client-secret teste123 --hydra-admin-url http://localhost:4445/ --hydra-public-url http://localhost:4444/ > token.json
```
The command above will store the generated token as a file called `token.json`.

# Use it with docker

To use it with Docker, you can add the utility in build time and call it with the `ENTRYPOINT`.

Dockerfile Example:

```
...
from abilioesteves/whisper-client:0.0.1 as whisper-client

from alpine

COPY --from=whisper-client /whisper-client /

RUN touch token.json
ENTRYPOINT ["/whisper-client", " > ", "token.json"]
...

```




