export NO_THREADS = 1

all: Release/btc_ice_wallet

clean:
	$(MAKE) -C phc-winner-argon2 clean
	rm -f Release/btc_ice_wallet

Release/btc_ice_wallet: btc_ice_wallet.c phc-winner-argon2/libargon2.a
	mkdir -p $(@D)
	$(CC) -O2 -pipe -std=c99 -Werror -DNDEBUG -Iphc-winner-argon2/include -lssl -o $(@) btc_ice_wallet.c phc-winner-argon2/libargon2.a

phc-winner-argon2/libargon2.a: phc-winner-argon2
	cd $(@D); git pull
	$(MAKE) -C $(@D)

phc-winner-argon2:
	git submodule update --init
#	git clone git@github.com:P-H-C/phc-winner-argon2.git
