unit debug.info.reader.pe;

(*
 * Copyright (c) 2026
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *)

// -----------------------------------------------------------------------------
//
//      TDebugInfoPEReader
//
// -----------------------------------------------------------------------------
// Reads debug info embedded inside a compiled PE image (.exe/.dll/.bpl),
// Win32 and Win64. Two embed formats are auto-detected:
//
//   * JEDI/JCL:  a section named "JCLDEBUG" whose raw content is the exact
//                same JDBG blob as a standalone .jdbg file. Delegated to
//                TDebugInfoJdbgReader.
//
//   * madExcept: a resource of type "MAD", name "EXCEPT" holding the
//                compressed/encrypted map blob. Delegated to
//                TDebugInfoMadExceptReader.
//
// The plain ".map" and standalone ".jdbg"/madExcept ".mad" cases are handled
// by the existing map/jdbg/madexcept readers.
// -----------------------------------------------------------------------------

interface

{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([])}

uses
  System.Classes,
  debug.info,
  debug.info.reader;

type
  TDebugInfoPEReader = class(TDebugInfoReader)
  private
    procedure LoadFromMemory(DebugInfo: TDebugInfo; Base: PByte; Size: NativeInt);
  public
    procedure LoadFromStream(Stream: TStream; DebugInfo: TDebugInfo); override;
  end;

resourcestring
  sPENoDebugInfo = 'No embedded debug info found in PE image (looked for JCLDEBUG section and madExcept MAD/EXCEPT resource)';
  sPEInvalidImage = 'Not a valid PE image: %s';

implementation

uses
  Winapi.Windows,
  System.SysUtils,
  debug.info.reader.jdbg,
  debug.info.reader.madexcept;

const
  JclDebugSectionName: AnsiString = 'JCLDEBUG';
  MadExceptResType: string = 'MAD';
  MadExceptResName: string = 'EXCEPT';

// PE resource directory structures are not declared by Winapi.Windows.
const
  IMAGE_RESOURCE_NAME_IS_STRING    = DWORD($80000000);
  IMAGE_RESOURCE_DATA_IS_DIRECTORY = DWORD($80000000);

type
  PImageResourceDirectory = ^TImageResourceDirectory;
  TImageResourceDirectory = record
    Characteristics: DWORD;
    TimeDateStamp: DWORD;
    MajorVersion: Word;
    MinorVersion: Word;
    NumberOfNamedEntries: Word;
    NumberOfIdEntries: Word;
  end;

  PImageResourceDirectoryEntry = ^TImageResourceDirectoryEntry;
  TImageResourceDirectoryEntry = record
    Name: DWORD;         // high bit set: offset to name string; else integer id
    OffsetToData: DWORD; // high bit set: offset to subdirectory; else data entry
  end;

  PImageResourceDataEntry = ^TImageResourceDataEntry;
  TImageResourceDataEntry = record
    OffsetToData: DWORD; // RVA of the resource data
    Size: DWORD;
    CodePage: DWORD;
    Reserved: DWORD;
  end;

type
  // Minimal PE view over an in-memory image (file layout, not loaded layout).
  TPEImage = record
    Base: PByte;
    Size: NativeInt;
    Is64: Boolean;
    NumberOfSections: Integer;
    Sections: PImageSectionHeader;        // first section header
    DataDirectory: PImageDataDirectory;   // first data directory entry
    NumberOfRvaAndSizes: Cardinal;

    function CheckBounds(P: Pointer; Len: NativeInt): Boolean;
    function Parse(ABase: PByte; ASize: NativeInt): Boolean;
    function Section(Index: Integer): PImageSectionHeader;
    // Locate a section by (8 char, null padded) name
    function FindSection(const AName: AnsiString): PImageSectionHeader;
    // Translate an RVA to a pointer into the in-memory file image
    function RvaToPtr(Rva: Cardinal): PByte;
  end;

function TPEImage.CheckBounds(P: Pointer; Len: NativeInt): Boolean;
begin
  Result := (NativeUInt(P) >= NativeUInt(Base)) and
            (NativeUInt(P) + NativeUInt(Len) <= NativeUInt(Base) + NativeUInt(Size));
end;

function TPEImage.Parse(ABase: PByte; ASize: NativeInt): Boolean;
begin
  Result := False;

  Base := ABase;
  Size := ASize;

  if (Size < SizeOf(TImageDosHeader)) then
    Exit;

  var DosHeader := PImageDosHeader(Base);
  if (DosHeader._lfanew <= 0) or (DosHeader._lfanew >= Size) then
    Exit;
  // "MZ"
  if (PWord(Base)^ <> IMAGE_DOS_SIGNATURE) then
    Exit;

  var NtBase := Base + DosHeader._lfanew;
  // "PE\0\0" + FileHeader
  if (not CheckBounds(NtBase, SizeOf(DWORD) + SizeOf(TImageFileHeader))) then
    Exit;
  if (PDWORD(NtBase)^ <> IMAGE_NT_SIGNATURE) then
    Exit;

  var FileHeader := PImageFileHeader(NtBase + SizeOf(DWORD));
  NumberOfSections := FileHeader.NumberOfSections;

  var OptHeader := PByte(FileHeader) + SizeOf(TImageFileHeader);
  if (not CheckBounds(OptHeader, SizeOf(Word))) then
    Exit;

  var Magic := PWord(OptHeader)^;
  Is64 := (Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC);

  if (Is64) then
  begin
    var Opt := PImageOptionalHeader64(OptHeader);
    NumberOfRvaAndSizes := Opt.NumberOfRvaAndSizes;
    DataDirectory := @Opt.DataDirectory[0];
  end else
  begin
    var Opt := PImageOptionalHeader32(OptHeader);
    NumberOfRvaAndSizes := Opt.NumberOfRvaAndSizes;
    DataDirectory := @Opt.DataDirectory[0];
  end;

  // Section headers follow the optional header
  Sections := PImageSectionHeader(OptHeader + FileHeader.SizeOfOptionalHeader);
  if (not CheckBounds(Sections, SizeOf(TImageSectionHeader) * NumberOfSections)) then
    Exit;

  Result := True;
end;

function TPEImage.Section(Index: Integer): PImageSectionHeader;
begin
  Result := PImageSectionHeader(PByte(Sections) + Index * SizeOf(TImageSectionHeader));
end;

function TPEImage.FindSection(const AName: AnsiString): PImageSectionHeader;
begin
  for var i := 0 to NumberOfSections-1 do
  begin
    var Sec := Section(i);
    // Section names are 8 bytes, null padded (not necessarily null terminated)
    var Name: string := '';
    for var k := 0 to IMAGE_SIZEOF_SHORT_NAME-1 do
    begin
      var C := AnsiChar(Sec.Name[k]);
      if (C = #0) then
        break;
      Name := Name + Char(C);
    end;
    if (SameText(Name, string(AName))) then
      Exit(Sec);
  end;
  Result := nil;
end;

function TPEImage.RvaToPtr(Rva: Cardinal): PByte;
begin
  for var i := 0 to NumberOfSections-1 do
  begin
    var Sec := Section(i);
    var VSize := Sec.Misc.VirtualSize;
    if (VSize = 0) then
      VSize := Sec.SizeOfRawData;
    if (Rva >= Sec.VirtualAddress) and (Rva < Sec.VirtualAddress + VSize) then
    begin
      var FileOffset := Sec.PointerToRawData + (Rva - Sec.VirtualAddress);
      var P := Base + FileOffset;
      if (CheckBounds(P, 0)) then
        Exit(P);
      Exit(nil);
    end;
  end;
  Result := nil;
end;


// -----------------------------------------------------------------------------
//      Resource directory traversal (find MAD/EXCEPT)
// -----------------------------------------------------------------------------

// Compare a resource directory string (UTF-16, word length prefixed) to AName
function ResourceNameMatches(ResBase: PByte; Entry: PImageResourceDirectoryEntry; const AName: string): Boolean;
begin
  // Only string-named entries can match a named resource
  if (Entry.Name and IMAGE_RESOURCE_NAME_IS_STRING = 0) then
    Exit(False);

  var StrPtr := ResBase + (Entry.Name and (not IMAGE_RESOURCE_NAME_IS_STRING));
  var Len := PWord(StrPtr)^;
  var Chars := PWideChar(StrPtr + SizeOf(Word));
  var S: string;
  SetString(S, Chars, Len);
  Result := SameText(S, AName);
end;

type
  PResDirEntryArray = ^TResDirEntryArray;
  TResDirEntryArray = array[0..High(Word)] of TImageResourceDirectoryEntry;

// Find the entry matching AName within the directory at DirPtr; returns the
// entry or nil.
function FindResourceEntry(ResBase, DirPtr: PByte; const AName: string): PImageResourceDirectoryEntry;
begin
  var Dir := PImageResourceDirectory(DirPtr);
  var Count := Dir.NumberOfNamedEntries + Dir.NumberOfIdEntries;
  var Entries := PResDirEntryArray(DirPtr + SizeOf(TImageResourceDirectory));
  for var i := 0 to Count-1 do
    if (ResourceNameMatches(ResBase, @Entries[i], AName)) then
      Exit(@Entries[i]);
  Result := nil;
end;

// Descend to the first leaf (data entry) under a directory node
function FirstLeaf(ResBase: PByte; Entry: PImageResourceDirectoryEntry): PImageResourceDataEntry;
begin
  Result := nil;
  var Ofs := Entry.OffsetToData;
  while (Ofs and IMAGE_RESOURCE_DATA_IS_DIRECTORY <> 0) do
  begin
    var Dir := PImageResourceDirectory(ResBase + (Ofs and (not IMAGE_RESOURCE_DATA_IS_DIRECTORY)));
    if (Dir.NumberOfNamedEntries + Dir.NumberOfIdEntries = 0) then
      Exit;
    var Entries := PResDirEntryArray(PByte(Dir) + SizeOf(TImageResourceDirectory));
    Entry := @Entries[0];
    Ofs := Entry.OffsetToData;
  end;
  Result := PImageResourceDataEntry(ResBase + Ofs);
end;

// -----------------------------------------------------------------------------

procedure TDebugInfoPEReader.LoadFromMemory(DebugInfo: TDebugInfo; Base: PByte; Size: NativeInt);
begin
  var Image: TPEImage;
  if (not Image.Parse(Base, Size)) then
    raise EDebugInfo.CreateFmt(sPEInvalidImage, ['bad DOS/NT headers']);

  if (Image.Is64) then
    Logger.Info('PE image: Win64')
  else
    Logger.Info('PE image: Win32');

  // -----------------------------------------------------------------
  // 1) JEDI / JCL: JCLDEBUG section
  // -----------------------------------------------------------------
  var Section := Image.FindSection(JclDebugSectionName);
  if (Section <> nil) then
  begin
    var DataSize := Section.Misc.VirtualSize;
    if (DataSize = 0) then
      DataSize := Section.SizeOfRawData;

    var P := Base + Section.PointerToRawData;
    if (not Image.CheckBounds(P, DataSize)) then
      raise EDebugInfo.CreateFmt(sPEInvalidImage, ['JCLDEBUG section out of bounds']);

    Logger.Info('Found embedded JEDI/JCL debug info (JCLDEBUG section, %.0n bytes)', [DataSize * 1.0]);

    var Stream := TMemoryStream.Create;
    try
      Stream.WriteBuffer(P^, DataSize);
      Stream.Position := 0;

      var Reader := TDebugInfoJdbgReader.Create;
      try
        Reader.LoadFromStream(Stream, DebugInfo);
      finally
        Reader.Free;
      end;
    finally
      Stream.Free;
    end;

    Exit;
  end;

  // -----------------------------------------------------------------
  // 2) madExcept: MAD/EXCEPT resource
  // -----------------------------------------------------------------
  if (IMAGE_DIRECTORY_ENTRY_RESOURCE < Integer(Image.NumberOfRvaAndSizes)) then
  begin
    var ResDir := PImageDataDirectory(PByte(Image.DataDirectory) + IMAGE_DIRECTORY_ENTRY_RESOURCE * SizeOf(TImageDataDirectory));
    if (ResDir.VirtualAddress <> 0) and (ResDir.Size <> 0) then
    begin
      var ResBase := Image.RvaToPtr(ResDir.VirtualAddress);
      if (ResBase <> nil) then
      begin
        // Level 1: resource type "MAD"
        var TypeEntry := FindResourceEntry(ResBase, ResBase, MadExceptResType);
        if (TypeEntry <> nil) and (TypeEntry.OffsetToData and IMAGE_RESOURCE_DATA_IS_DIRECTORY <> 0) then
        begin
          var NameDir := ResBase + (TypeEntry.OffsetToData and (not IMAGE_RESOURCE_DATA_IS_DIRECTORY));
          // Level 2: resource name "EXCEPT"
          var NameEntry := FindResourceEntry(ResBase, NameDir, MadExceptResName);
          if (NameEntry <> nil) then
          begin
            var Leaf := FirstLeaf(ResBase, NameEntry);
            if (Leaf <> nil) then
            begin
              var DataPtr := Image.RvaToPtr(Leaf.OffsetToData);
              if (DataPtr <> nil) and (Image.CheckBounds(DataPtr, Leaf.Size)) then
              begin
                Logger.Info('Found embedded madExcept debug info (MAD/EXCEPT resource, %.0n bytes)', [Leaf.Size * 1.0]);

                var Stream := TMemoryStream.Create;
                try
                  Stream.WriteBuffer(DataPtr^, Leaf.Size);
                  Stream.Position := 0;

                  var Reader := TDebugInfoMadExceptReader.Create;
                  try
                    Reader.LoadFromStream(Stream, DebugInfo);
                  finally
                    Reader.Free;
                  end;
                finally
                  Stream.Free;
                end;

                Exit;
              end;
            end;
          end;
        end;
      end;
    end;
  end;

  raise EDebugInfo.Create(sPENoDebugInfo);
end;

// -----------------------------------------------------------------------------

procedure TDebugInfoPEReader.LoadFromStream(Stream: TStream; DebugInfo: TDebugInfo);
begin
  Logger.Info('Reading PE image');

  var MemoryStream: TMemoryStream := nil;
  var Buffer: TMemoryStream;

  if (Stream is TMemoryStream) and (Stream.Position = 0) then
    Buffer := TMemoryStream(Stream)
  else
  begin
    MemoryStream := TMemoryStream.Create;
    Buffer := MemoryStream;
    MemoryStream.CopyFrom(Stream, Stream.Size - Stream.Position);
    MemoryStream.Position := 0;
  end;

  try
    LoadFromMemory(DebugInfo, PByte(Buffer.Memory), Buffer.Size);
  finally
    MemoryStream.Free;
  end;
end;

end.
