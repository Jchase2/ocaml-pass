(* Copyright (C) 2015 JChase2
This code is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public
License as published by the Free Software Foundation; either
version 2 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details. *)

open Nocrypto.Cipher_block
open Printf
   
(* ============================== GLOBAL EXPRESSIONS ========================== *)
let cryptfile = "ocamlpass.crypt"
let kbf = Buffer.create 500 
let keystore = ref "" (* Always encrypted. *)
let knum = ref 0 (* Randomly generated increment initialized on start, used to ensure random creation of key. *)
let filebuff = Buffer.create 500

(* Help Dialogue *)
let help = [
    " ";
    "Type 'read' to read the entire file.";
    "Type 'stringsearch' to search for and print a string.";
    "Type 'blocksearch' to search for and print a block.";
    "Type 'block' to insert a new block.";
    "Type 'insert' to insert new lines into a block.";
    "Type 'removeblock' to remove a block.";
    "Type 'removestring' to remove string(s) from a block.";
    "Type 'listblocks' to list all block headers."; 
    "Type 'q' to quit."
]

(* =============================== Crypt Utilities ============================================= *)

(* dectohex and hex2dec are just associative lists to get values for
hex, which are used for padding, except G which is added so it's still a single char.
Am considering replacing these with a map, although they're small so performance is fine. 
Takes int, gives char. 
*)
    
let dectohex (x) =
  let hexlist =
    [1, '1'; 2, '2'; 3, '3'; 4, '4'; 5, '5';
     6, '6'; 7, '7'; 8, '8'; 9, '9'; 10, 'A';
     11, 'B'; 12, 'C'; 13, 'D'; 14, 'E'; 15, 'F'; 16, 'G'] in 
  let ret = List.assoc x hexlist in
(ret)

let hextodec (x) =
  let hexlist =
    ['1', 1; '2', 2; '3', 3; '4', 4; '5', 5; '6', 6;
     '7', 7; '8', 8; '9', 9; 'A', 10; 'B', 11; 'C', 12;
     'D', 13; 'E', 14; 'F', 15; 'G', 16] in
  let ret = List.assoc x hexlist in
(ret)
    
(* Copies bytes to buffer, except the first 16 bytes. *)
(* This essentially helps remove the IV prior to decryption. *)
(* Not memory secure. *)
let removeiv bytestream buff () =
  for i = 16 to ((Bytes.length bytestream - 1)) do
    Buffer.add_char buff (Bytes.get bytestream i)
  done ;
()

(* Recursive function to get padding length. *)
let padlen message () =
  let i = ref 0 in
  let rec loop () =
    let bytelength = (Cstruct.len message) in
    if ((bytelength mod 16) = 0) then
      begin
        i := 16;
        ()
      end
    else if ((bytelength + !i) mod 16) != 0 then
      begin
        i := (!i + 1);
        loop ()
      end ;
  in
  loop();
(!i)

(* Read cryptfile into a bytestream, stores in filebuff. *)
let load_file () =
  let ic = open_in_gen [Open_creat] 0o664 cryptfile in
  let n = in_channel_length ic in
  let s = Bytes.create n in
  really_input ic s 0 n;
  close_in ic;
  Buffer.add_bytes filebuff s;
()
         
(* =============================== Encryption / Decryption ========================== *)

(* This takes a given cstruct and encrypts it. *)
(* Returns string of ciphertext with IV prepended. *)
(* Quickcrypt and quickdecrypt are used to more securely store the key for file encryption. *)
(* Takes a cstruct. *)
let quickcrypt (message) =
  let () = Nocrypto_entropy_unix.initialize () in
  let randnum = Nocrypto.Rng.generate 16 in (* Random numbers *)
  let iv = (Cstruct.sub (Nocrypto.Hash.SHA256.digest randnum)0 16) in (* Hash of randnum *)
  let paddingsize = padlen message () in
  let paddingbyte = dectohex paddingsize in
  let padding = Bytes.make paddingsize paddingbyte in
  (* Session key generation *)
  let sesk = (Cstruct.create 32) in
  (* Creates a key from randomly generated kbf buffer at randomly generated increment. *)
  for i = 0 to 31 do
    Cstruct.set_char sesk i (Buffer.nth kbf  (i + !knum));                          
  done;
  let key =  AES.CBC.of_secret sesk in  
  let text_with_padding = Cstruct.create ((Cstruct.len message) + paddingsize) in
  Cstruct.blit message 0 text_with_padding 0 (Cstruct.len message);
  Cstruct.blit_from_string padding 0 text_with_padding (Cstruct.len message) paddingsize;
  let ciphertext = AES.CBC.encrypt ~key ~iv text_with_padding in
  let cipher_iv = (Cstruct.to_string iv) ^ (Cstruct.to_string ciphertext) in
  (* Clean up. *)
  Cstruct.memset sesk 0;
  Cstruct.memset text_with_padding 0;
  Cstruct.memset ciphertext 0;
(cipher_iv)

(* Decrypts quickcrypt encrypted stuff, returns plaintext cstruct. *)
(* Takes a regular string of ciphertext. *)
let quickdecrypt (cipher) =
  let s = cipher in
  let a = String.sub cipher 16 ((String.length cipher) - 16) in (* Get cipher without IV *)
  let iv = (Cstruct.of_string (Bytes.sub_string s 0 16)) in (* This is the iv *)
  (* Session key generation *)
  let sesk = (Cstruct.create 32) in
  (* Creates a key from randomly generated kbf buffer at randomly generated increment. *)
  for i = 0 to 31 do
    Cstruct.set_char sesk i (Buffer.nth kbf  (i + !knum));                          
  done;
  let key =  AES.CBC.of_secret sesk in
  let txt_with_padding = AES.CBC.decrypt ~key ~iv (Cstruct.of_string a) in
  let lastbyte = Cstruct.get_char txt_with_padding ((Cstruct.len txt_with_padding)-1) in
  let toremove = hextodec lastbyte in
  let textcstr = Cstruct.sub txt_with_padding 0 ((Cstruct.len txt_with_padding)-toremove) in
  (* Clean up a bit. *)
  Cstruct.memset sesk 0;
  Cstruct.memset txt_with_padding 0;
  Cstruct.memset iv 0;
(textcstr)

let decrypt_check () =
  if ((Buffer.length filebuff) > 0) then
    ()
  else
      print_endline "File is empty.";
()
 

(* Decrypts file, returns plaintext cstruct. *)
let decrypt_file () =
  load_file ();
  decrypt_check ();
  let s = Buffer.contents filebuff in
  let localbuff = Buffer.create 500 in
  removeiv s localbuff ();
  (* Set up decryption parameters *)
  let iv = (Cstruct.of_string (Bytes.sub_string s 0 16)) in
  let mykey = (quickdecrypt !keystore) in
  let key = AES.CBC.of_secret mykey in (* Generate usable key from mykey. *)
  (* txtpadding is decrypted file with padding still included...*)
  Cstruct.memset mykey 0; (* Zero out mykey *)
  let txt_with_padding = AES.CBC.decrypt ~key ~iv (Cstruct.of_string (Buffer.contents localbuff)) in
  let lastbyte = Cstruct.get_char txt_with_padding ((Cstruct.len txt_with_padding)-1) in
  print_char lastbyte;
  let toremove = hextodec lastbyte in
  let textcstr = Cstruct.sub txt_with_padding 0 ((Cstruct.len txt_with_padding)-toremove) in
  Buffer.clear localbuff ;
  (* Clean up *)
  Cstruct.memset iv 0;
  Cstruct.memset txt_with_padding 0;
(textcstr)  

(* Encrypt contents of cstruct, write to file. *)
(* Prepend IV, append padding. *)
(* Replaces contents of cryptfile with contents of passed in cstruct. *)
let encrypt cstrstring () =
  let () = Nocrypto_entropy_unix.initialize () in
  let randnum = Nocrypto.Rng.generate 16 in (* Random numbers *)
  let iv = (Cstruct.sub (Nocrypto.Hash.SHA256.digest randnum)0 16) in (* Hash of randnum *)
  let mykey = (quickdecrypt !keystore) in
  let key = AES.CBC.of_secret mykey in (* Generate usable key from mykey *)
  let paddingsize = padlen cstrstring () in
  let paddingbyte = dectohex paddingsize in    
  let padding = Bytes.make paddingsize paddingbyte in
  let text_with_padding = Cstruct.create ((Cstruct.len cstrstring) + paddingsize) in
  Cstruct.blit cstrstring 0 text_with_padding 0 (Cstruct.len cstrstring);
  Cstruct.blit_from_string padding 0 text_with_padding (Cstruct.len cstrstring) paddingsize;
  let ciphertext = AES.CBC.encrypt ~key ~iv text_with_padding in
  let cipher_iv = (Cstruct.to_string iv) ^ (Cstruct.to_string ciphertext) in
  (* Clean up. *)
  Cstruct.memset mykey 0;
  Cstruct.memset text_with_padding 0;
  Cstruct.memset ciphertext 0;
  let oc = open_out cryptfile in
  output_string oc (cipher_iv);
  flush oc;
  close_out oc;
()
 
             
(* ============================== UTILITIES =========================== *)


(* Safely prints a string. Takes a cstruct, works by side effect. *)
let safe_print_string (str) =
  print_endline "";
  let a = Core.Bigstring.write Unix.stdout (Cstruct.to_bigarray str) in
  print_endline "";
()

(* PRINT LIST STRING *)
(* Not memory secure. *)
let rec print_list_string mylist () = match mylist with
  | [] -> print_endline " "
  | head::body ->
     begin
       print_endline head;
       print_list_string body
     end
()


let read () =
  let file = decrypt_file () in
  safe_print_string file;
()
    
(* ======================== Insertion / Searching Functions ========================= *)
 
(* Have to redo everything because memory security lol. *)
    
(* =============================== MAIN and Configure ============================ *)

(* Main interaction loop via tail recursion. *)
(* Mostly just a large if statement... *)
(* More functional alternative? *)

let rec main_loop () =
  print_endline "";
  print_endline "Type '?' or 'help' to print dialogue box. ";
  print_string "Command: ";
  let str = read_line () in
  if str = "exit" then begin
      Gc.full_major ();
      exit 0;
      ()
    end
  else if str = "quit" then
    begin
      Gc.full_major ();
      exit 0;
      ()
    end
  else if str = "q" then
    begin
      Gc.full_major ();
      exit 0;
      ()
    end
  else if str = "help" then begin
      print_list_string help ();
      main_loop ()
    end
  else if str = "?" then begin
      print_list_string help ();
      main_loop ()
    end
  else if str = "read" then begin
      read();
      main_loop()
    end
  else if str = "testing" then begin
      load_file();
      main_loop ()
    end
  else begin
      print_endline "";
      print_endline "That is not a defined option. ";
      main_loop ()
    end;
()
  
(* Configure pw, generate scrypt key, decrypt and load in file on launch. *)
let login () =
  let salt = (Cstruct.of_string "rN)K_=BPCeQj83SbA)zi-Zgd8S88`ZFWI;+uK/1}H#w&?ATgo9|=zT(y+2DjlO|O") in
  let n = 16384 (* CPU / memory cost Parameter *) in
  let r = 8 (* Specifies the block size in bytes for scrypt *) in
  let p = 4 (* Paralellization parameter for scrypt. *) in
  let dk_len = 32l (* Length of key, 8 * blocksize = 256. Is AES Max key size. *) in
  print_endline "";
  print_string "Password: ";
  let password = (Cstruct.of_string (read_line())) in (* Not memory secure, replace with Unix module function.*)
  let () = Nocrypto_entropy_unix.initialize () in
  (* Add 47 bytes to kbf to generate a random session key from. *)
  let rkn = 47 in
  for i = 0 to rkn do
    Buffer.add_string kbf (Cstruct.to_string (Nocrypto.Rng.generate 8));
  done;
  (* Generate a random number between 0 and 6 to help generate random increment to
     draw a key from. *)
  Random.self_init ();
  knum := (Random.int 6);
  let mykey = (Scrypt_kdf.scrypt_kdf ~password ~salt ~n ~r ~p ~dk_len) in
  Cstruct.memset password 0; (* Zero out password. *)
  keystore := quickcrypt mykey;
  Cstruct.memset mykey 0; (* Zero out mykey *)
  load_file ();
  print_endline "Logged in. ";
  main_loop() ;
;; 

login();
main_loop()


