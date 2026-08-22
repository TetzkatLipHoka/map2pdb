unit debug.info.utilities;

(*
 * Copyright (c) 2021 Anders Melander
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *)

interface

uses
  debug.info,
  debug.info.log;


// -----------------------------------------------------------------------------
//
//      FilterModules
//
// -----------------------------------------------------------------------------
// Remove modules from debug info based on name and segment.
// -----------------------------------------------------------------------------
procedure FilterModules(DebugInfo: TDebugInfo; const ModuleFilter: string; Include: boolean; Logger: IDebugInfoModuleLogger);


// -----------------------------------------------------------------------------
//
//      PostImportValidation
//
// -----------------------------------------------------------------------------
// Perform variaous validation on debug info.
// -----------------------------------------------------------------------------
procedure PostImportValidation(DebugInfo: TDebugInfo; Logger: IDebugInfoModuleLogger);


// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------

implementation

uses
  System.Generics.Collections,
  System.Masks,
  System.SysUtils,
  System.StrUtils;

// -----------------------------------------------------------------------------
//
//      FilterModules
//
// -----------------------------------------------------------------------------
procedure FilterModules(DebugInfo: TDebugInfo; const ModuleFilter: string; Include: boolean; Logger: IDebugInfoModuleLogger);
var
  MaskValues: TArray<string>;
  SymbolsIncludeEliminateCount: integer;
  SymbolsExcludeEliminateCount: integer;
  ModulesIncludeEliminateCount: integer;
  ModulesExcludeEliminateCount: integer;
  Masks: TObjectList<TMask>;
  Segments: TList<Word>;
  MaskValue: string;
  Segment: integer;
  i: integer;
  Module: TDebugInfoModule;
  KeepIt: boolean;
  Mask: TMask;
  Segment2: Word;
begin
  try
    MaskValues := ModuleFilter.Split([';']);

    SymbolsIncludeEliminateCount := 0;
    SymbolsExcludeEliminateCount := 0;
    ModulesIncludeEliminateCount := 0;
    ModulesExcludeEliminateCount := 0;

    Masks := TObjectList<TMask>.Create;
    Segments := TList<Word>.Create;
    try
      Masks.Capacity := Length(MaskValues);
      for MaskValue in MaskValues do
      begin
        if (MaskValue.Length = 4) and (TryStrToInt(MaskValue, Segment)) and (Segment <= $FFFF) then
          Segments.Add(Segment)
        else
          Masks.Add(TMask.Create(MaskValue));
      end;

      for i := DebugInfo.Modules.Count-1 downto 0 do
      begin
        Module := DebugInfo.Modules[i];
        KeepIt := not Include;

        for Mask in Masks do
          if (Mask.Matches(Module.Name)) then
          begin
            KeepIt := Include;
            break;
          end;

        if (KeepIt = not Include) then
          for Segment2 in Segments do
            if (Module.Segment.Index = Segment2) then
            begin
              KeepIt := Include;
              break;
            end;

        if (not KeepIt) then
        begin
          if (Include) then
          begin
            Inc(ModulesIncludeEliminateCount);
            Inc(SymbolsIncludeEliminateCount, Module.Symbols.Count);
            Logger.Debug('Include filter eliminated module: [%.4X] %s', [Module.Segment.Index, Module.Name])
          end else
          begin
            Inc(ModulesExcludeEliminateCount);
            Inc(SymbolsExcludeEliminateCount, Module.Symbols.Count);
            Logger.Debug('Exclude filter eliminated module: [%.4X] %s', [Module.Segment.Index, Module.Name]);
          end;

          DebugInfo.Modules.Remove(Module);
        end;
      end;
    finally
      Segments.Free;
      Masks.Free;
    end;

    if (ModulesIncludeEliminateCount > 0) then
      Logger.Info('Include filter eliminated %.0n module(s), %.0n symbol(s)', [ModulesIncludeEliminateCount * 1.0, SymbolsIncludeEliminateCount * 1.0]);

    if (ModulesExcludeEliminateCount > 0) then
      Logger.Info('Exclude filter eliminated %.0n module(s), %.0n symbols(s)', [ModulesExcludeEliminateCount * 1.0, SymbolsExcludeEliminateCount * 1.0]);

  except
    on E: EMaskException do
      Logger.Error('Invalid filter. %s', [E.Message]);
  end;
end;

// -----------------------------------------------------------------------------
//
//      PostImportValidation
//
// -----------------------------------------------------------------------------
procedure PostImportValidation(DebugInfo: TDebugInfo; Logger: IDebugInfoModuleLogger);
var
  Module: TDebugInfoModule;
begin
  // Modules with lines but no source or vice versa
  for Module in DebugInfo.Modules do
  begin
    if (Module.SourceFiles.Count = 0) then
    begin
      if (Module.SourceLines.Count = 0) then
        Logger.Debug('Module has no source files: [%.4X] %s', [Module.Segment.Index, Module.Name])
      else
        Logger.Debug('Module has source lines but no source file: [%.4X] %s', [Module.Segment.Index, Module.Name]);
    end else
    if (Module.SourceLines.Count = 0) then
      Logger.Debug('Module has source files but no source lines: [%.4X] %s', [Module.Segment.Index, Module.Name]);
  end;
end;

// -----------------------------------------------------------------------------

end.

