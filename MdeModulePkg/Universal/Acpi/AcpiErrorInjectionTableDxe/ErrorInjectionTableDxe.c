/** @file
  This module installs ACPI Error Injection Table (EINJ)

  Copyright (c) 2025, Ventana Micro Systems, Inc.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Base.h>
#include <Uefi.h>

#include <IndustryStandard/Acpi.h>

#include <Protocol/AcpiTable.h>

#include <Guid/EventGroup.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>
#include <Library/SafeIntLib.h>
#include <Library/BaseRiscVSbiLib.h>

#include <Library/DxeRiscvMpxy.h>
#include <Library/DxeRiscvRasAgentClient.h>

EFI_EVENT                      mEinjReadyToBootEvent;
UINTN                          mEinjTableKey = 0;
BOOLEAN                        mAcpiEinjInstalled            = FALSE;
BOOLEAN                        mAcpiEinjStatusChanged        = FALSE;
BOOLEAN                        mAcpiEinjBufferChanged        = FALSE;

#define STATUS_BLOCK_SIZE      1024
#define MPXY_SHMEM_SIZE        4096

//
// ACPI Error Injection Table template
//
EFI_ACPI_6_5_ERROR_INJECTION_TABLE_HEADER  mEinjTemplate = {
  {
    EFI_ACPI_6_5_ERROR_INJECTION_TABLE_SIGNATURE,
    sizeof (EFI_ACPI_6_5_ERROR_INJECTION_TABLE_HEADER),
    EFI_ACPI_6_5_ERROR_INJECTION_TABLE_REVISION, // Revision
    0x00,                               // Checksum will be updated at runtime
    //
    // It is expected that these values will be updated at EntryPoint.
    //
    { 0x00 },   // OEM ID is a 6 bytes long field
    0x00,       // OEM Table ID(8 bytes long)
    0x00,       // OEM Revision
    0x00,       // Creator ID
    0x00,       // Creator Revision
  },
  0             // Number of error source
};

/**
  Notify function for event group EFI_EVENT_GROUP_READY_TO_BOOT. This is used to
  install the Hardware Error Source Table.

  @param[in]  Event   The Event that is being processed.
  @param[in]  Context The Event Context.

**/
VOID
EinjReadyToBootEventNotify (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  EFI_STATUS               Status;
  EFI_ACPI_TABLE_PROTOCOL  *AcpiTableProtocol;
  EFI_ACPI_DESCRIPTION_HEADER  *Header;
  UINT32 NumInstructions;
  INTN i;
  VOID *EinjTable;
  UINT32 EinjPages, EinjTableSize;
  EFI_ACPI_6_5_EINJ_INJECTION_INSTRUCTION_ENTRY *BaseEntry, *tBaseEntry;
  EFI_ACPI_6_5_ERROR_INJECTION_TABLE_HEADER *EinjHdr;
  VOID *Inst;
  UINT32 InstSize;
#define EINJ_TO_BASE_INJECTION_ACTION_TABLE(_table)			\
  (EFI_ACPI_6_5_EINJ_INJECTION_INSTRUCTION_ENTRY *)			\
	  ((UINT8 *)_table +						\
	   sizeof(EFI_ACPI_6_5_ERROR_INJECTION_TABLE_HEADER));

  Header = &mEinjTemplate.Header;

  //
  // Get ACPI Table protocol.
  //
  Status = gBS->LocateProtocol (
                  &gEfiAcpiTableProtocolGuid,
                  NULL,
                  (VOID **)&AcpiTableProtocol
                  );
  if (EFI_ERROR (Status)) {
    return;
  }

  //
  // Check if HEST is already installed.
  //
  if (mAcpiEinjInstalled) {
    Status = AcpiTableProtocol->UninstallAcpiTable (
                                  AcpiTableProtocol,
                                  mEinjTableKey
                                  );
      if (EFI_ERROR (Status)) {
        return;
      }
  }

  // Initialize the RAS agent client library.
  Status = RacInit ();
  if (EFI_ERROR (Status)) {
    return;
  }

  // Fetch the number of hardware error sources available
  Status = RacGetNumberErrorInjectionEntries(&NumInstructions);
  if (EFI_ERROR (Status)) {
    return;
  }

  mEinjTemplate.InjectionEntryCount = NumInstructions;

  // Allocate memory for all the error source descriptors
  EinjTableSize = sizeof(mEinjTemplate) +
    sizeof(EFI_ACPI_6_5_EINJ_INJECTION_INSTRUCTION_ENTRY)
    * NumInstructions;

  EinjPages = EFI_SIZE_TO_PAGES(EinjTableSize);
  EinjTable = AllocateAlignedPages(EinjPages, 4096);

  if (EinjTable == NULL) {
    return;
  }

  EinjHdr = (EFI_ACPI_6_5_ERROR_INJECTION_TABLE_HEADER *)EinjTable;
  CopyMem (EinjTable, &mEinjTemplate, sizeof(mEinjTemplate));
  EinjHdr->InjectionHeaderSize = sizeof(mEinjTemplate);
  EinjHdr->InjectionFlags = 0;
  EinjHdr->InjectionEntryCount = NumInstructions;

  tBaseEntry = BaseEntry = EINJ_TO_BASE_INJECTION_ACTION_TABLE(EinjTable);

  for (i = 0; i < NumInstructions; i++) {
    Status = RacGetEinjInstruction (i, &Inst, &InstSize);
    if (EFI_ERROR(Status)) {
      return;
    }

    CopyMem (tBaseEntry, Inst, InstSize);
    tBaseEntry++;
  }

  Header = &((typeof(mEinjTemplate) *)EinjTable)->Header;
  Header->Length = EinjTableSize;

  //
  // Update Checksum in Hest Table
  //
  Header->Checksum = 0;
  Header->Checksum =
    CalculateCheckSum8 (
      (UINT8 *)&EinjTable,
      EinjTableSize
      );

  //
  // Publish Boot Graphics Resource Table.
  //
  Status = AcpiTableProtocol->InstallAcpiTable (
                                AcpiTableProtocol,
                                EinjTable,
                                EinjTableSize,
                                &mEinjTableKey
                                );
  if (EFI_ERROR (Status)) {
    return;
  }

  mAcpiEinjInstalled     = TRUE;
}

/**
  The module Entry Point of the Boot Graphics Resource Table DXE driver.

  @param[in]  ImageHandle    The firmware allocated handle for the EFI image.
  @param[in]  SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS    The entry point is executed successfully.
  @retval Other          Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
ErrorInjectionDxeEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                   Status;
  EFI_ACPI_DESCRIPTION_HEADER  *Header;

  //
  // Update Header fields of HEST
  //
  Header = &mEinjTemplate.Header;
  ZeroMem (Header->OemId, sizeof (Header->OemId));
  CopyMem (
    Header->OemId,
    PcdGetPtr (PcdAcpiDefaultOemId),
    MIN (PcdGetSize (PcdAcpiDefaultOemId), sizeof (Header->OemId))
    );

  WriteUnaligned64 (&Header->OemTableId, PcdGet64 (PcdAcpiDefaultOemTableId));
  Header->OemRevision     = PcdGet32 (PcdAcpiDefaultOemRevision);
  Header->CreatorId       = PcdGet32 (PcdAcpiDefaultCreatorId);
  Header->CreatorRevision = PcdGet32 (PcdAcpiDefaultCreatorRevision);

  //
  // Register notify function to install EINJ on ReadyToBoot Event.
  //
  Status = gBS->CreateEventEx (
                  EVT_NOTIFY_SIGNAL,
                  TPL_CALLBACK,
                  EinjReadyToBootEventNotify,
                  NULL,
                  &gEfiEventReadyToBootGuid,
                  &mEinjReadyToBootEvent
                  );
  ASSERT_EFI_ERROR (Status);

  return Status;
}
