--  hadawallet entry point.
--
--  v0.1: smoke test. Loads a test private key, demonstrates that
--  the Has_Key boolean flips, runs the (stub) Comm loop, exits.

with Ada.Text_IO;

with Hadawallet;
with Signing;
with Comm;

procedure Main is

   Test_Key : constant Hadawallet.Privkey_Bytes := [others => 16#42#];

begin
   Ada.Text_IO.Put_Line ("hadawallet v0.1-dev (skeleton)");
   Ada.Text_IO.Put_Line ("formally verified Bitcoin hardware wallet firmware");
   Ada.Text_IO.New_Line;

   Ada.Text_IO.Put_Line
     ("[smoke-test] Has_Key before load = "
      & Boolean'Image (Signing.Has_Key));

   Signing.Load_Privkey (Test_Key);
   Ada.Text_IO.Put_Line
     ("[smoke-test] Has_Key after load  = "
      & Boolean'Image (Signing.Has_Key));

   Signing.Wipe;
   Ada.Text_IO.Put_Line
     ("[smoke-test] Has_Key after wipe  = "
      & Boolean'Image (Signing.Has_Key));

   Ada.Text_IO.New_Line;
   Comm.Run;
end Main;
