Vendored libopus 1.3.1 (fixed-point subset) for the stadia-one-uac worktree.

Provenance
  source   : opus 1.3.1 upstream tarball via the Tsinghua Debian mirror
             https://mirrors.tuna.tsinghua.edu.cn/debian/pool/main/o/opus/opus_1.3.1.orig.tar.gz
             (github.com direct was unreachable from this network)
  sha256   : 65b58e1e25b2a114157014736a3d9dfeaad8d41be1c8179866f144a2fb44ff9d
             matches opus_1.3.1-3.dsc (Debian) and the published upstream hash.
  license  : COPYING here is the upstream BSD-3-Clause text, unmodified.

Contents (the fixed-point encoder/decoder build set, exactly the upstream
silk_sources.mk / celt_sources.mk / opus_sources.mk "generic fixed" entries,
minus multistream/projection and minus the x86/ARM intrinsics subdirectories):
  include/    opus.h opus_defines.h opus_types.h opus_multistream.h
  src/        opus.c opus_encoder.c opus_decoder.c analysis.c mlp.c mlp_data.c
  celt/       CELT_SOURCES (18 .c) + top-level celt headers
  silk/       SILK_SOURCES common .c + silk/*.h, silk/fixed/* (SILK_SOURCES_FIXED)
Excluded: silk/float/, celt/x86/, celt/arm/, *mips*, multistream/projection
sources, docs, tests, autotools files.

Build flags used by ../CMakeLists.txt: OPUS_BUILD, FIXED_POINT,
NONTHREADSAFE_PSEUDOSTACK, GLOBAL_STACK_SIZE=40960, PACKAGE_VERSION="1.3.1".
No config.h (no HAVE_CONFIG_H). p3-3641-core0encode: VAR_ARRAYS=1 was replaced
by the pseudostack build because the Opus encode moved to core0, whose stack is
the SDK's 4 KiB SCRATCH_Y one (celt/stack_alloc.h, celt/arch.h).

Stadia patches (both marked "STADIA PATCH" in the source)
  silk/fixed/encode_frame_FIX.c: the two silk_nsq_state temporaries in
  silk_encode_frame_FIX and the one in silk_LBRR_encode_FIX (4,704 B each) are
  allocated with ALLOC()/VARDECL on the pseudostack instead of being plain
  locals. As locals they made a 9,408 B FIXED stack frame which the pseudostack
  cannot cover - fatal on core0's 4 KiB stack. Fixed frame: 9,408 -> 748 B.
