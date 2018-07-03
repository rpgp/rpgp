# Makefile.am - For tests/openpgp
# Copyright (C) 1998, 1999, 2000, 2001, 2003,
#               2010 Free Software Foundation, Inc.
#
# This file is part of GnuPG.
#
# GnuPG is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# GnuPG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.
# Process this file with automake to create Makefile.in


# Programs required before we can run these tests.
required_pgms = ../../g10/gpg$(EXEEXT) ../../agent/gpg-agent$(EXEEXT) \
                ../../tools/gpg-connect-agent$(EXEEXT) \
		../gpgscm/gpgscm$(EXEEXT)

AM_CPPFLAGS = -I$(top_srcdir)/common
include $(top_srcdir)/am/cmacros.am

AM_CFLAGS =

noinst_PROGRAMS = fake-pinentry

fake_pinentry_SOURCES = fake-pinentry.c

TESTS_ENVIRONMENT = LC_ALL=C \
	EXEEXT=$(EXEEXT) \
	PATH=../gpgscm:$(PATH) \
	abs_top_srcdir=$(abs_top_srcdir) \
	objdir=$(abs_top_builddir) \
	GPGSCM_PATH=$(abs_top_srcdir)/tests/gpgscm

XTESTS = \
	version.scm \
	enarmor.scm \
	mds.scm \
	decrypt.scm \
	decrypt-multifile.scm \
	decrypt-dsa.scm \
	decrypt-session-key.scm \
	decrypt-unwrap-verify.scm \
	sigs.scm \
	sigs-dsa.scm \
	encrypt.scm \
	encrypt-multifile.scm \
	encrypt-dsa.scm \
	compression.scm \
	seat.scm \
	clearsig.scm \
	encryptp.scm \
	detach.scm \
	detachm.scm \
	armsigs.scm \
	armencrypt.scm \
	armencryptp.scm \
	signencrypt.scm \
	signencrypt-dsa.scm \
	armsignencrypt.scm \
	armdetach.scm \
	armdetachm.scm \
	genkey1024.scm \
	conventional.scm \
	conventional-mdc.scm \
	multisig.scm \
	verify.scm \
	verify-multifile.scm \
	gpgv.scm \
	gpgv-forged-keyring.scm \
	armor.scm \
	import.scm \
	import-revocation-certificate.scm \
	ecc.scm \
	4gb-packet.scm \
	tofu.scm \
	trust-pgp-1.scm \
	trust-pgp-2.scm \
	trust-pgp-3.scm \
	gpgtar.scm \
	use-exact-key.scm \
	default-key.scm \
	export.scm \
	ssh-import.scm \
	ssh-export.scm \
	quick-key-manipulation.scm \
	key-selection.scm \
	delete-keys.scm \
	gpgconf.scm \
	issue2015.scm \
	issue2346.scm \
	issue2417.scm \
	issue2419.scm \
	issue2929.scm \
	issue2941.scm


# XXX: Currently, one cannot override automake's 'check' target.  As a
# workaround, we avoid defining 'TESTS', thus automake will not emit
# the 'check' target.  For extra robustness, we merely define a
# dependency on 'xcheck', so this hack should also work even if
# automake would emit the 'check' target, as adding dependencies to
# targets is okay.
check: xcheck

.PHONY: xcheck
xcheck:
	$(TESTS_ENVIRONMENT) $(abs_top_builddir)/tests/gpgscm/gpgscm \
	  $(abs_srcdir)/run-tests.scm $(TESTFLAGS) $(TESTS)

TEST_FILES = pubring.asc secring.asc plain-1o.asc plain-2o.asc plain-3o.asc \
	     plain-1.asc plain-2.asc plain-3.asc plain-1-pgp.asc \
	     plain-largeo.asc plain-large.asc \
	     pubring.pkr.asc secring.skr.asc secdemo.asc pubdemo.asc \
	     bug537-test.data.asc bug894-test.asc \
	     bug1223-good.asc bug1223-bogus.asc 4gb-packet.asc \
	     tofu/conflicting/1C005AF3.gpg \
	     tofu/conflicting/1C005AF3-secret.gpg \
	     tofu/conflicting/1C005AF3-1.txt \
	     tofu/conflicting/1C005AF3-2.txt \
	     tofu/conflicting/1C005AF3-3.txt \
	     tofu/conflicting/1C005AF3-4.txt \
	     tofu/conflicting/1C005AF3-5.txt \
	     tofu/conflicting/B662E42F.gpg \
	     tofu/conflicting/B662E42F-secret.gpg \
	     tofu/conflicting/B662E42F-1.txt \
	     tofu/conflicting/B662E42F-2.txt \
	     tofu/conflicting/B662E42F-3.txt \
	     tofu/conflicting/B662E42F-4.txt \
	     tofu/conflicting/B662E42F-5.txt \
	     tofu/conflicting/BE04EB2B.gpg \
	     tofu/conflicting/BE04EB2B-secret.gpg \
	     tofu/conflicting/BE04EB2B-1.txt \
	     tofu/conflicting/BE04EB2B-2.txt \
	     tofu/conflicting/BE04EB2B-3.txt \
	     tofu/conflicting/BE04EB2B-4.txt \
	     tofu/conflicting/BE04EB2B-5.txt \
	     tofu/cross-sigs/EC38277E-secret.gpg \
	     tofu/cross-sigs/EC38277E-1.gpg \
	     tofu/cross-sigs/EC38277E-1.txt \
	     tofu/cross-sigs/EC38277E-2.gpg \
	     tofu/cross-sigs/EC38277E-2.txt \
	     tofu/cross-sigs/EC38277E-3.txt \
	     tofu/cross-sigs/871C2247-secret.gpg \
	     tofu/cross-sigs/871C2247-1.gpg \
	     tofu/cross-sigs/871C2247-1.txt \
	     tofu/cross-sigs/871C2247-2.gpg \
	     tofu/cross-sigs/871C2247-2.txt \
	     tofu/cross-sigs/871C2247-3.gpg \
	     tofu/cross-sigs/871C2247-3.txt \
	     tofu/cross-sigs/871C2247-4.gpg \
	     tofu/cross-sigs/README \
	     key-selection/0.asc \
	     key-selection/1.asc \
	     key-selection/2.asc \
	     key-selection/3.asc \
	     key-selection/4.asc \
	     trust-pgp/scenario1.asc \
	     trust-pgp/scenario2.asc \
	     trust-pgp/scenario3.asc \
	     trust-pgp/scenario4.asc \
	     trust-pgp/alice.sec.asc \
	     trust-pgp/bobby.sec.asc \
	     trust-pgp/carol.sec.asc \
	     trust-pgp/david.sec.asc \
	     trust-pgp/frank.sec.asc \
	     trust-pgp/grace.sec.asc \
	     trust-pgp/heidi.sec.asc

data_files = data-500 data-9000 data-32000 data-80000 plain-large

priv_keys = privkeys/50B2D4FA4122C212611048BC5FC31BD44393626E.asc \
            privkeys/7E201E28B6FEB2927B321F443205F4724EBE637E.asc \
            privkeys/13FDB8809B17C5547779F9D205C45F47CE0217CE.asc \
            privkeys/343D8AF79796EE107D645A2787A9D9252F924E6F.asc \
            privkeys/8B5ABF3EF9EB8D96B91A0B8C2C4401C91C834C34.asc \
            privkeys/0D6F6AD4C4C803B25470F9104E9F4E6A4CA64255.asc \
            privkeys/FD692BD59D6640A84C8422573D469F84F3B98E53.asc \
            privkeys/76F7E2B35832976B50A27A282D9B87E44577EB66.asc \
            privkeys/A0747D5F9425E6664F4FFBEED20FBCA79FDED2BD.asc \
	    privkeys/0DD40284FF992CD24DC4AAC367037E066FCEE26A.asc \
	    privkeys/2BC997C0B8691D41D29A4EC81CCBCF08454E4961.asc \
	    privkeys/3C9D5ECA70130C2DBB1FC6AC0076BEEEC197716F.asc \
	    privkeys/449E644892C951A37525654730DD32C202079926.asc \
	    privkeys/58FFE844087634E62440224908BDE44BEA7EB730.asc \
	    privkeys/4DF9172D6FF428C97A0E9AA96F03E8BCE3B2F188.asc \
	    privkeys/9D7CD8F53F2F14C3E2177D1E9D1D11F39513A4A4.asc \
	    privkeys/6E6B7ED0BD4425018FFC54F3921D5467A3AE00EB.asc \
	    privkeys/C905D0AB6AE9655C5A35975939997BBF3325D6DD.asc \
	    privkeys/B2BAA7144303DF19BB6FDE23781DD3FDD97918D4.asc \
	    privkeys/CF60965BF51F67CF80DECE853E0D2D343468571D.asc \
	    privkeys/DF00E361D34F80868D06879AC21D7A7D4E4FAD76.asc \
	    privkeys/00FE67F28A52A8AA08FFAED20AF832DA916D1985.asc \
	    privkeys/1DF48228FEFF3EC2481B106E0ACA8C465C662CC5.asc \
	    privkeys/A2832820DC9F40751BDCD375BB0945BA33EC6B4C.asc \
	    privkeys/ADE710D74409777B7729A7653373D820F67892E0.asc \
	    privkeys/CEFC51AF91F68A2904FBFF62C4F075A4785B803F.asc \
            privkeys/1E28F20E41B54C2D1234D896096495FF57E08D18.asc \
            privkeys/EB33B687EB8581AB64D04852A54453E85F3DF62D.asc \
	    privkeys/C6A6390E9388CDBAD71EAEA698233FE5E04F001E.asc \
	    privkeys/D69102E0F5AC6B6DB8E4D16DA8E18CF46D88CAE3.asc

sample_keys = samplekeys/README \
              samplekeys/ecc-sample-1-pub.asc \
              samplekeys/ecc-sample-2-pub.asc \
              samplekeys/ecc-sample-3-pub.asc \
              samplekeys/ecc-sample-1-sec.asc \
              samplekeys/ecc-sample-2-sec.asc \
              samplekeys/ecc-sample-3-sec.asc \
	      samplekeys/eddsa-sample-1-pub.asc \
	      samplekeys/eddsa-sample-1-sec.asc \
	      samplekeys/dda252ebb8ebe1af-1.asc \
	      samplekeys/dda252ebb8ebe1af-2.asc \
	      samplekeys/whats-new-in-2.1.asc \
	      samplekeys/e2e-p256-1-clr.asc \
	      samplekeys/e2e-p256-1-prt.asc \
	      samplekeys/E657FB607BB4F21C90BB6651BC067AF28BC90111.asc \
              samplekeys/rsa-rsa-sample-1.asc \
              samplekeys/ed25519-cv25519-sample-1.asc \
	      samplekeys/silent-running.asc \
	      samplekeys/ssh-dsa.key \
	      samplekeys/ssh-ecdsa.key \
	      samplekeys/ssh-ed25519.key \
	      samplekeys/ssh-rsa.key \
	      samplekeys/issue2346.gpg \
	      samplekeys/authenticate-only.pub.asc \
	      samplekeys/authenticate-only.sec.asc

sample_msgs = samplemsgs/clearsig-1-key-1.asc \
	      samplemsgs/clearsig-2-keys-1.asc \
	      samplemsgs/clearsig-2-keys-2.asc \
	      samplemsgs/enc-1-key-1.asc \
	      samplemsgs/enc-1-key-2.asc \
	      samplemsgs/enc-2-keys-1.asc \
	      samplemsgs/enc-2-keys-2.asc \
	      samplemsgs/enc-2-keys-hh-1.asc \
	      samplemsgs/enc-2-keys-hr-1.asc \
	      samplemsgs/enc-2-keys-rh-1.asc \
	      samplemsgs/encsig-2-2-keys-3.asc \
	      samplemsgs/encsig-2-2-keys-4.asc \
	      samplemsgs/encsig-2-keys-1.asc \
	      samplemsgs/encsig-2-keys-2.asc \
	      samplemsgs/encsig-2-keys-3.asc \
	      samplemsgs/encsig-2-keys-4.asc \
	      samplemsgs/encz0-1-key-1.asc \
	      samplemsgs/encz0-1-key-2.asc \
	      samplemsgs/issue2419.asc \
	      samplemsgs/revoke-2D727CC768697734.asc \
	      samplemsgs/sig-1-key-1.asc \
	      samplemsgs/sig-1-key-2.asc \
	      samplemsgs/sig-2-keys-1.asc \
	      samplemsgs/sig-2-keys-2.asc \
	      samplemsgs/signed-1-key-1.asc \
	      samplemsgs/signed-1-key-2.asc \
	      samplemsgs/signed-2-keys-1.asc \
	      samplemsgs/signed-2-keys-2.asc

EXTRA_DIST = defs.scm trust-pgp/common.scm $(XTESTS) $(TEST_FILES) \
	     mkdemodirs signdemokey $(priv_keys) $(sample_keys)   \
	     $(sample_msgs) ChangeLog-2011 run-tests.scm \
	     setup.scm shell.scm all-tests.scm signed-messages.scm

CLEANFILES = prepared.stamp x y yy z out err  $(data_files) \
	     plain-1 plain-2 plain-3 trustdb.gpg *.lock .\#lk* \
	     *.log gpg_dearmor gpg.conf gpg-agent.conf S.gpg-agent \
	     pubring.gpg pubring.gpg~ pubring.kbx pubring.kbx~ \
	     secring.gpg pubring.pkr secring.skr \
	     gnupg-test.stop random_seed gpg-agent.log tofu.db \
	     passphrases sshcontrol S.gpg-agent.ssh report.xml

if DISABLE_REGEX
EXTRA_DIST += trust-pgp-4.scm
else
XTESTS += trust-pgp-4.scm
endif

clean-local:
	-rm -rf private-keys-v1.d openpgp-revocs.d tofu.d gpgtar.d


# We need to depend on a couple of programs so that the tests don't
# start before all programs are built.
all-local: $(required_pgms)
