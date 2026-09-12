# devcontainer


For format details, see https://aka.ms/devcontainer.json.

``` json
{
	"name": "OpenVox Module Development",
	"dockerFile": "Dockerfile",

	// Set *default* container specific settings.json values on container create.
	"settings": {
		"terminal.integrated.profiles.linux": {
			"bash": {
				"path": "bash",
			}
		}
	},

	// Add the IDs of extensions you want installed when the container is created.
	"extensions": [
		"puppet.puppet-vscode",
		"rebornix.Ruby"
	],

	// Use 'postCreateCommand' to run commands after the container is created.
	"postCreateCommand": "bundle install"
}
```
