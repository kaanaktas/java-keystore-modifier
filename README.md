# java-keystore-processor

Command base Java Keystore(JKS) modifier. It imports key pairs to specified java keystore.

# Import Steps and Warnings
1- Key needs to be converted to DER format
	openssl pkcs8 -topk8 -inform PEM -outform DER -in rsaprivkey.pem -out rsaprivkey.der -nocrypt
2- Run JksModifier via Java. If no argument passed, the usage of command appears.
	java JKSModifierUsage
		>Usage: java ImportKey [keyfile] [certfile] [alias] [keystore] [keypass] reset(optional)

