all: btc_ice_wallet

btc_ice_wallet: btc_ice_wallet.c
	$(CC) -O2 -pipe $< -o $@ -lssl
