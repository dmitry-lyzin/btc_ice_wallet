all: Release/btc_ice_wallet

Release/btc_ice_wallet: btc_ice_wallet.c
	mkdir -p $(@D)
	$(CC) -O2 -pipe -lssl -DNDEBUG -o $(@) $(?)
