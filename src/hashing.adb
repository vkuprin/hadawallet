--  Hashing body — pure-Ada cryptographic primitives.
--
--  SPARK_Mode => Off for v0.1: implementations are correct (verified against
--  RFC/FIPS test vectors) but Gold-level proofs on the bit-twiddling loops
--  are deferred. The spec retains explicit Global => null / Depends contracts
--  so callers can prove their own flow contracts against this module.

pragma Style_Checks ("-s");
--  Disable -gnatys (specs-required) for this file. Internal helpers
--  (Put_Be32, SHA256_Compress, etc.) are package-private and live nowhere
--  else; mandating a separate declaration would just duplicate the signature.

with Interfaces; use Interfaces;

package body Hashing
  with SPARK_Mode => Off
is

   use type Hadawallet.U8;

   ---------------------------------------------------------------------------
   --  SHA-256 (FIPS 180-4)
   ---------------------------------------------------------------------------

   type SHA256_State is array (0 .. 7) of Unsigned_32;
   type SHA256_Schedule is array (0 .. 63) of Unsigned_32;

   K256 : constant SHA256_Schedule :=
     [16#428a2f98#,
      16#71374491#,
      16#b5c0fbcf#,
      16#e9b5dba5#,
      16#3956c25b#,
      16#59f111f1#,
      16#923f82a4#,
      16#ab1c5ed5#,
      16#d807aa98#,
      16#12835b01#,
      16#243185be#,
      16#550c7dc3#,
      16#72be5d74#,
      16#80deb1fe#,
      16#9bdc06a7#,
      16#c19bf174#,
      16#e49b69c1#,
      16#efbe4786#,
      16#0fc19dc6#,
      16#240ca1cc#,
      16#2de92c6f#,
      16#4a7484aa#,
      16#5cb0a9dc#,
      16#76f988da#,
      16#983e5152#,
      16#a831c66d#,
      16#b00327c8#,
      16#bf597fc7#,
      16#c6e00bf3#,
      16#d5a79147#,
      16#06ca6351#,
      16#14292967#,
      16#27b70a85#,
      16#2e1b2138#,
      16#4d2c6dfc#,
      16#53380d13#,
      16#650a7354#,
      16#766a0abb#,
      16#81c2c92e#,
      16#92722c85#,
      16#a2bfe8a1#,
      16#a81a664b#,
      16#c24b8b70#,
      16#c76c51a3#,
      16#d192e819#,
      16#d6990624#,
      16#f40e3585#,
      16#106aa070#,
      16#19a4c116#,
      16#1e376c08#,
      16#2748774c#,
      16#34b0bcb5#,
      16#391c0cb3#,
      16#4ed8aa4a#,
      16#5b9cca4f#,
      16#682e6ff3#,
      16#748f82ee#,
      16#78a5636f#,
      16#84c87814#,
      16#8cc70208#,
      16#90befffa#,
      16#a4506ceb#,
      16#bef9a3f7#,
      16#c67178f2#];

   IV256 : constant SHA256_State :=
     [16#6a09e667#,
      16#bb67ae85#,
      16#3c6ef372#,
      16#a54ff53a#,
      16#510e527f#,
      16#9b05688c#,
      16#1f83d9ab#,
      16#5be0cd19#];

   function Be32 (B : Hadawallet.Byte_Array; I : Positive) return Unsigned_32
   is (Shift_Left (Unsigned_32 (B (I)), 24)
       or Shift_Left (Unsigned_32 (B (I + 1)), 16)
       or Shift_Left (Unsigned_32 (B (I + 2)), 8)
       or Unsigned_32 (B (I + 3)));

   procedure Put_Be32
     (Out_Buf : in out Hadawallet.Byte_Array; I : Positive; V : Unsigned_32) is
   begin
      Out_Buf (I) := Hadawallet.U8 (Shift_Right (V, 24) and 16#FF#);
      Out_Buf (I + 1) := Hadawallet.U8 (Shift_Right (V, 16) and 16#FF#);
      Out_Buf (I + 2) := Hadawallet.U8 (Shift_Right (V, 8) and 16#FF#);
      Out_Buf (I + 3) := Hadawallet.U8 (V and 16#FF#);
   end Put_Be32;

   procedure SHA256_Compress
     (State : in out SHA256_State; Block : Hadawallet.Byte_Array)
   is
      W                       : SHA256_Schedule;
      A, B, C, D, E, F, G, H  : Unsigned_32;
      S0, S1, Ch, Maj, T1, T2 : Unsigned_32;
   begin
      for I in 0 .. 15 loop
         W (I) := Be32 (Block, Block'First + I * 4);
      end loop;
      for I in 16 .. 63 loop
         S0 :=
           Rotate_Right (W (I - 15), 7)
           xor Rotate_Right (W (I - 15), 18)
           xor Shift_Right (W (I - 15), 3);
         S1 :=
           Rotate_Right (W (I - 2), 17)
           xor Rotate_Right (W (I - 2), 19)
           xor Shift_Right (W (I - 2), 10);
         W (I) := W (I - 16) + S0 + W (I - 7) + S1;
      end loop;

      A := State (0);
      B := State (1);
      C := State (2);
      D := State (3);
      E := State (4);
      F := State (5);
      G := State (6);
      H := State (7);

      for I in 0 .. 63 loop
         S1 :=
           Rotate_Right (E, 6)
           xor Rotate_Right (E, 11)
           xor Rotate_Right (E, 25);
         Ch := (E and F) xor ((not E) and G);
         T1 := H + S1 + Ch + K256 (I) + W (I);
         S0 :=
           Rotate_Right (A, 2)
           xor Rotate_Right (A, 13)
           xor Rotate_Right (A, 22);
         Maj := (A and B) xor (A and C) xor (B and C);
         T2 := S0 + Maj;

         H := G;
         G := F;
         F := E;
         E := D + T1;
         D := C;
         C := B;
         B := A;
         A := T1 + T2;
      end loop;

      State (0) := State (0) + A;
      State (1) := State (1) + B;
      State (2) := State (2) + C;
      State (3) := State (3) + D;
      State (4) := State (4) + E;
      State (5) := State (5) + F;
      State (6) := State (6) + G;
      State (7) := State (7) + H;
   end SHA256_Compress;

   procedure SHA256
     (Input : in Hadawallet.Byte_Array; Out_Hash : out Hadawallet.Digest_Bytes)
   is
      State    : SHA256_State := IV256;
      Bit_Len  : constant Unsigned_64 := Unsigned_64 (Input'Length) * 8;
      Tail_Len : constant Natural :=
        (if (Input'Length mod 64) < 56
         then 64 - (Input'Length mod 64)
         else 128 - (Input'Length mod 64));
      Padded   : Hadawallet.Byte_Array (1 .. Input'Length + Tail_Len) :=
        [others => 0];
   begin
      if Input'Length > 0 then
         Padded (1 .. Input'Length) := Input;
      end if;
      Padded (Input'Length + 1) := 16#80#;
      for I in 0 .. 7 loop
         Padded (Padded'Last - 7 + I) :=
           Hadawallet.U8 (Shift_Right (Bit_Len, 56 - I * 8) and 16#FF#);
      end loop;

      declare
         Num_Blocks : constant Natural := Padded'Length / 64;
      begin
         for B in 0 .. Num_Blocks - 1 loop
            SHA256_Compress
              (State,
               Padded (Padded'First + B * 64 .. Padded'First + B * 64 + 63));
         end loop;
      end;

      for I in 0 .. 7 loop
         Put_Be32
           (Hadawallet.Byte_Array (Out_Hash),
            Out_Hash'First + I * 4,
            State (I));
      end loop;
   end SHA256;

   ---------------------------------------------------------------------------
   --  SHA-512 (FIPS 180-4) — used by HMAC-SHA512
   ---------------------------------------------------------------------------

   type SHA512_State is array (0 .. 7) of Unsigned_64;
   type SHA512_Schedule is array (0 .. 79) of Unsigned_64;

   K512 : constant SHA512_Schedule :=
     [16#428a2f98d728ae22#,
      16#7137449123ef65cd#,
      16#b5c0fbcfec4d3b2f#,
      16#e9b5dba58189dbbc#,
      16#3956c25bf348b538#,
      16#59f111f1b605d019#,
      16#923f82a4af194f9b#,
      16#ab1c5ed5da6d8118#,
      16#d807aa98a3030242#,
      16#12835b0145706fbe#,
      16#243185be4ee4b28c#,
      16#550c7dc3d5ffb4e2#,
      16#72be5d74f27b896f#,
      16#80deb1fe3b1696b1#,
      16#9bdc06a725c71235#,
      16#c19bf174cf692694#,
      16#e49b69c19ef14ad2#,
      16#efbe4786384f25e3#,
      16#0fc19dc68b8cd5b5#,
      16#240ca1cc77ac9c65#,
      16#2de92c6f592b0275#,
      16#4a7484aa6ea6e483#,
      16#5cb0a9dcbd41fbd4#,
      16#76f988da831153b5#,
      16#983e5152ee66dfab#,
      16#a831c66d2db43210#,
      16#b00327c898fb213f#,
      16#bf597fc7beef0ee4#,
      16#c6e00bf33da88fc2#,
      16#d5a79147930aa725#,
      16#06ca6351e003826f#,
      16#142929670a0e6e70#,
      16#27b70a8546d22ffc#,
      16#2e1b21385c26c926#,
      16#4d2c6dfc5ac42aed#,
      16#53380d139d95b3df#,
      16#650a73548baf63de#,
      16#766a0abb3c77b2a8#,
      16#81c2c92e47edaee6#,
      16#92722c851482353b#,
      16#a2bfe8a14cf10364#,
      16#a81a664bbc423001#,
      16#c24b8b70d0f89791#,
      16#c76c51a30654be30#,
      16#d192e819d6ef5218#,
      16#d69906245565a910#,
      16#f40e35855771202a#,
      16#106aa07032bbd1b8#,
      16#19a4c116b8d2d0c8#,
      16#1e376c085141ab53#,
      16#2748774cdf8eeb99#,
      16#34b0bcb5e19b48a8#,
      16#391c0cb3c5c95a63#,
      16#4ed8aa4ae3418acb#,
      16#5b9cca4f7763e373#,
      16#682e6ff3d6b2b8a3#,
      16#748f82ee5defb2fc#,
      16#78a5636f43172f60#,
      16#84c87814a1f0ab72#,
      16#8cc702081a6439ec#,
      16#90befffa23631e28#,
      16#a4506cebde82bde9#,
      16#bef9a3f7b2c67915#,
      16#c67178f2e372532b#,
      16#ca273eceea26619c#,
      16#d186b8c721c0c207#,
      16#eada7dd6cde0eb1e#,
      16#f57d4f7fee6ed178#,
      16#06f067aa72176fba#,
      16#0a637dc5a2c898a6#,
      16#113f9804bef90dae#,
      16#1b710b35131c471b#,
      16#28db77f523047d84#,
      16#32caab7b40c72493#,
      16#3c9ebe0a15c9bebc#,
      16#431d67c49c100d4c#,
      16#4cc5d4becb3e42b6#,
      16#597f299cfc657e2a#,
      16#5fcb6fab3ad6faec#,
      16#6c44198c4a475817#];

   IV512 : constant SHA512_State :=
     [16#6a09e667f3bcc908#,
      16#bb67ae8584caa73b#,
      16#3c6ef372fe94f82b#,
      16#a54ff53a5f1d36f1#,
      16#510e527fade682d1#,
      16#9b05688c2b3e6c1f#,
      16#1f83d9abfb41bd6b#,
      16#5be0cd19137e2179#];

   function Be64 (B : Hadawallet.Byte_Array; I : Positive) return Unsigned_64
   is
      R : Unsigned_64 := 0;
   begin
      for K in 0 .. 7 loop
         R := Shift_Left (R, 8) or Unsigned_64 (B (I + K));
      end loop;
      return R;
   end Be64;

   procedure Put_Be64
     (Out_Buf : in out Hadawallet.Byte_Array; I : Positive; V : Unsigned_64) is
   begin
      for K in 0 .. 7 loop
         Out_Buf (I + K) :=
           Hadawallet.U8 (Shift_Right (V, 56 - K * 8) and 16#FF#);
      end loop;
   end Put_Be64;

   procedure SHA512_Compress
     (State : in out SHA512_State; Block : Hadawallet.Byte_Array)
   is
      W                       : SHA512_Schedule;
      A, B, C, D, E, F, G, H  : Unsigned_64;
      S0, S1, Ch, Maj, T1, T2 : Unsigned_64;
   begin
      for I in 0 .. 15 loop
         W (I) := Be64 (Block, Block'First + I * 8);
      end loop;
      for I in 16 .. 79 loop
         S0 :=
           Rotate_Right (W (I - 15), 1)
           xor Rotate_Right (W (I - 15), 8)
           xor Shift_Right (W (I - 15), 7);
         S1 :=
           Rotate_Right (W (I - 2), 19)
           xor Rotate_Right (W (I - 2), 61)
           xor Shift_Right (W (I - 2), 6);
         W (I) := W (I - 16) + S0 + W (I - 7) + S1;
      end loop;

      A := State (0);
      B := State (1);
      C := State (2);
      D := State (3);
      E := State (4);
      F := State (5);
      G := State (6);
      H := State (7);

      for I in 0 .. 79 loop
         S1 :=
           Rotate_Right (E, 14)
           xor Rotate_Right (E, 18)
           xor Rotate_Right (E, 41);
         Ch := (E and F) xor ((not E) and G);
         T1 := H + S1 + Ch + K512 (I) + W (I);
         S0 :=
           Rotate_Right (A, 28)
           xor Rotate_Right (A, 34)
           xor Rotate_Right (A, 39);
         Maj := (A and B) xor (A and C) xor (B and C);
         T2 := S0 + Maj;

         H := G;
         G := F;
         F := E;
         E := D + T1;
         D := C;
         C := B;
         B := A;
         A := T1 + T2;
      end loop;

      State (0) := State (0) + A;
      State (1) := State (1) + B;
      State (2) := State (2) + C;
      State (3) := State (3) + D;
      State (4) := State (4) + E;
      State (5) := State (5) + F;
      State (6) := State (6) + G;
      State (7) := State (7) + H;
   end SHA512_Compress;

   procedure SHA512
     (Input    : in Hadawallet.Byte_Array;
      Out_Hash : out Hadawallet.Mac_Bytes_512)
   is
      State    : SHA512_State := IV512;
      Bit_Len  : constant Unsigned_64 := Unsigned_64 (Input'Length) * 8;
      Tail_Len : constant Natural :=
        (if (Input'Length mod 128) < 112
         then 128 - (Input'Length mod 128)
         else 256 - (Input'Length mod 128));
      Padded   : Hadawallet.Byte_Array (1 .. Input'Length + Tail_Len) :=
        [others => 0];
   begin
      if Input'Length > 0 then
         Padded (1 .. Input'Length) := Input;
      end if;
      Padded (Input'Length + 1) := 16#80#;
      Put_Be64 (Padded, Padded'Last - 7, Bit_Len);

      declare
         Num_Blocks : constant Natural := Padded'Length / 128;
      begin
         for B in 0 .. Num_Blocks - 1 loop
            SHA512_Compress
              (State,
               Padded
                 (Padded'First + B * 128 .. Padded'First + B * 128 + 127));
         end loop;
      end;

      for I in 0 .. 7 loop
         Put_Be64
           (Hadawallet.Byte_Array (Out_Hash),
            Out_Hash'First + I * 8,
            State (I));
      end loop;
   end SHA512;

   ---------------------------------------------------------------------------
   --  HMAC-SHA512 (RFC 2104 + RFC 4231)
   ---------------------------------------------------------------------------

   procedure HMAC_SHA512
     (Key : in Hadawallet.Byte_Array;
      Msg : in Hadawallet.Byte_Array;
      Mac : out Hadawallet.Mac_Bytes_512)
   is
      Block_Size : constant := 128;
      K_Block    : Hadawallet.Byte_Array (1 .. Block_Size) := [others => 0];
      Ipad_Buf   : Hadawallet.Byte_Array (1 .. Block_Size + Msg'Length);
      Opad_Buf   : Hadawallet.Byte_Array (1 .. Block_Size + 64);
      Inner_Hash : Hadawallet.Mac_Bytes_512;
   begin
      if Key'Length > Block_Size then
         declare
            Short : Hadawallet.Mac_Bytes_512;
         begin
            SHA512 (Key, Short);
            K_Block (1 .. 64) := Hadawallet.Byte_Array (Short);
         end;
      else
         if Key'Length > 0 then
            K_Block (1 .. Key'Length) := Key;
         end if;
      end if;

      for I in 1 .. Block_Size loop
         Ipad_Buf (I) := K_Block (I) xor 16#36#;
      end loop;
      if Msg'Length > 0 then
         Ipad_Buf (Block_Size + 1 .. Block_Size + Msg'Length) := Msg;
      end if;
      SHA512 (Ipad_Buf, Inner_Hash);

      for I in 1 .. Block_Size loop
         Opad_Buf (I) := K_Block (I) xor 16#5c#;
      end loop;
      Opad_Buf (Block_Size + 1 .. Block_Size + 64) :=
        Hadawallet.Byte_Array (Inner_Hash);
      SHA512 (Opad_Buf, Mac);
   end HMAC_SHA512;

   ---------------------------------------------------------------------------
   --  RIPEMD-160
   ---------------------------------------------------------------------------

   type RIPEMD_State is array (0 .. 4) of Unsigned_32;

   IV_RIPEMD : constant RIPEMD_State :=
     [16#67452301#, 16#efcdab89#, 16#98badcfe#, 16#10325476#, 16#c3d2e1f0#];

   R_Left : constant array (0 .. 79) of Natural :=
     [0,
      1,
      2,
      3,
      4,
      5,
      6,
      7,
      8,
      9,
      10,
      11,
      12,
      13,
      14,
      15,
      7,
      4,
      13,
      1,
      10,
      6,
      15,
      3,
      12,
      0,
      9,
      5,
      2,
      14,
      11,
      8,
      3,
      10,
      14,
      4,
      9,
      15,
      8,
      1,
      2,
      7,
      0,
      6,
      13,
      11,
      5,
      12,
      1,
      9,
      11,
      10,
      0,
      8,
      12,
      4,
      13,
      3,
      7,
      15,
      14,
      5,
      6,
      2,
      4,
      0,
      5,
      9,
      7,
      12,
      2,
      10,
      14,
      1,
      3,
      8,
      11,
      6,
      15,
      13];

   R_Right : constant array (0 .. 79) of Natural :=
     [5,
      14,
      7,
      0,
      9,
      2,
      11,
      4,
      13,
      6,
      15,
      8,
      1,
      10,
      3,
      12,
      6,
      11,
      3,
      7,
      0,
      13,
      5,
      10,
      14,
      15,
      8,
      12,
      4,
      9,
      1,
      2,
      15,
      5,
      1,
      3,
      7,
      14,
      6,
      9,
      11,
      8,
      12,
      2,
      10,
      0,
      4,
      13,
      8,
      6,
      4,
      1,
      3,
      11,
      15,
      0,
      5,
      12,
      2,
      13,
      9,
      7,
      10,
      14,
      12,
      15,
      10,
      4,
      1,
      5,
      8,
      7,
      6,
      2,
      13,
      14,
      0,
      3,
      9,
      11];

   S_Left : constant array (0 .. 79) of Natural :=
     [11,
      14,
      15,
      12,
      5,
      8,
      7,
      9,
      11,
      13,
      14,
      15,
      6,
      7,
      9,
      8,
      7,
      6,
      8,
      13,
      11,
      9,
      7,
      15,
      7,
      12,
      15,
      9,
      11,
      7,
      13,
      12,
      11,
      13,
      6,
      7,
      14,
      9,
      13,
      15,
      14,
      8,
      13,
      6,
      5,
      12,
      7,
      5,
      11,
      12,
      14,
      15,
      14,
      15,
      9,
      8,
      9,
      14,
      5,
      6,
      8,
      6,
      5,
      12,
      9,
      15,
      5,
      11,
      6,
      8,
      13,
      12,
      5,
      12,
      13,
      14,
      11,
      8,
      5,
      6];

   S_Right : constant array (0 .. 79) of Natural :=
     [8,
      9,
      9,
      11,
      13,
      15,
      15,
      5,
      7,
      7,
      8,
      11,
      14,
      14,
      12,
      6,
      9,
      13,
      15,
      7,
      12,
      8,
      9,
      11,
      7,
      7,
      12,
      7,
      6,
      15,
      13,
      11,
      9,
      7,
      15,
      11,
      8,
      6,
      6,
      14,
      12,
      13,
      5,
      14,
      13,
      13,
      7,
      5,
      15,
      5,
      8,
      11,
      14,
      14,
      6,
      14,
      6,
      9,
      12,
      9,
      12,
      5,
      15,
      8,
      8,
      5,
      12,
      9,
      12,
      5,
      14,
      6,
      8,
      13,
      6,
      5,
      15,
      13,
      11,
      11];

   K_Left : constant array (0 .. 4) of Unsigned_32 :=
     [16#00000000#, 16#5a827999#, 16#6ed9eba1#, 16#8f1bbcdc#, 16#a953fd4e#];

   K_Right : constant array (0 .. 4) of Unsigned_32 :=
     [16#50a28be6#, 16#5c4dd124#, 16#6d703ef3#, 16#7a6d76e9#, 16#00000000#];

   function RIPEMD_F (J : Natural; X, Y, Z : Unsigned_32) return Unsigned_32 is
   begin
      if J < 16 then
         return X xor Y xor Z;
      elsif J < 32 then
         return (X and Y) or ((not X) and Z);
      elsif J < 48 then
         return (X or (not Y)) xor Z;
      elsif J < 64 then
         return (X and Z) or (Y and (not Z));
      else
         return X xor (Y or (not Z));
      end if;
   end RIPEMD_F;

   procedure RIPEMD_Compress
     (State : in out RIPEMD_State; Block : Hadawallet.Byte_Array)
   is
      X                  : array (0 .. 15) of Unsigned_32;
      AL, BL, CL, DL, EL : Unsigned_32;
      AR, BR, CR, DR, ER : Unsigned_32;
      T                  : Unsigned_32;
   begin
      for I in 0 .. 15 loop
         X (I) :=
           Unsigned_32 (Block (Block'First + I * 4))
           or Shift_Left (Unsigned_32 (Block (Block'First + I * 4 + 1)), 8)
           or Shift_Left (Unsigned_32 (Block (Block'First + I * 4 + 2)), 16)
           or Shift_Left (Unsigned_32 (Block (Block'First + I * 4 + 3)), 24);
      end loop;

      AL := State (0);
      BL := State (1);
      CL := State (2);
      DL := State (3);
      EL := State (4);
      AR := State (0);
      BR := State (1);
      CR := State (2);
      DR := State (3);
      ER := State (4);

      for J in 0 .. 79 loop
         T :=
           Rotate_Left
             (AL + RIPEMD_F (J, BL, CL, DL) + X (R_Left (J)) + K_Left (J / 16),
              S_Left (J))
           + EL;
         AL := EL;
         EL := DL;
         DL := Rotate_Left (CL, 10);
         CL := BL;
         BL := T;

         T :=
           Rotate_Left
             (AR
              + RIPEMD_F (79 - J, BR, CR, DR)
              + X (R_Right (J))
              + K_Right (J / 16),
              S_Right (J))
           + ER;
         AR := ER;
         ER := DR;
         DR := Rotate_Left (CR, 10);
         CR := BR;
         BR := T;
      end loop;

      T := State (1) + CL + DR;
      State (1) := State (2) + DL + ER;
      State (2) := State (3) + EL + AR;
      State (3) := State (4) + AL + BR;
      State (4) := State (0) + BL + CR;
      State (0) := T;
   end RIPEMD_Compress;

   procedure RIPEMD160
     (Input    : in Hadawallet.Byte_Array;
      Out_Hash : out Hadawallet.Hash160_Bytes)
   is
      State    : RIPEMD_State := IV_RIPEMD;
      Bit_Len  : constant Unsigned_64 := Unsigned_64 (Input'Length) * 8;
      Tail_Len : constant Natural :=
        (if (Input'Length mod 64) < 56
         then 64 - (Input'Length mod 64)
         else 128 - (Input'Length mod 64));
      Padded   : Hadawallet.Byte_Array (1 .. Input'Length + Tail_Len) :=
        [others => 0];
   begin
      if Input'Length > 0 then
         Padded (1 .. Input'Length) := Input;
      end if;
      Padded (Input'Length + 1) := 16#80#;
      for I in 0 .. 7 loop
         Padded (Padded'Last - 7 + I) :=
           Hadawallet.U8 (Shift_Right (Bit_Len, I * 8) and 16#FF#);
      end loop;

      declare
         Num_Blocks : constant Natural := Padded'Length / 64;
      begin
         for B in 0 .. Num_Blocks - 1 loop
            RIPEMD_Compress
              (State,
               Padded (Padded'First + B * 64 .. Padded'First + B * 64 + 63));
         end loop;
      end;

      for I in 0 .. 4 loop
         declare
            V    : constant Unsigned_32 := State (I);
            Base : constant Positive := Out_Hash'First + I * 4;
         begin
            Out_Hash (Base) := Hadawallet.U8 (V and 16#FF#);
            Out_Hash (Base + 1) :=
              Hadawallet.U8 (Shift_Right (V, 8) and 16#FF#);
            Out_Hash (Base + 2) :=
              Hadawallet.U8 (Shift_Right (V, 16) and 16#FF#);
            Out_Hash (Base + 3) :=
              Hadawallet.U8 (Shift_Right (V, 24) and 16#FF#);
         end;
      end loop;
   end RIPEMD160;

   ---------------------------------------------------------------------------
   --  Hash160 = RIPEMD-160(SHA-256(x))
   ---------------------------------------------------------------------------

   procedure Hash160
     (Input    : in Hadawallet.Byte_Array;
      Out_Hash : out Hadawallet.Hash160_Bytes)
   is
      Inter : Hadawallet.Digest_Bytes;
   begin
      SHA256 (Input, Inter);
      RIPEMD160 (Hadawallet.Byte_Array (Inter), Out_Hash);
   end Hash160;

end Hashing;
