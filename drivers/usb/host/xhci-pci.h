/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2019-2020 Linaro Limited */

#ifndef XHCI_PCI_H
#define XHCI_PCI_H

int renesas_xhci_pci_probe(struct pci_dev *dev,
			   const struct pci_device_id *id);
int renesas_xhci_pci_remove(struct pci_dev *dev);

int xhci_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id);

#endif

