import { Component, OnInit } from '@angular/core';
import { SmartContractService } from '../../smart-contract.service';
import { UserService } from '../../user.service';
import { MatSnackBar } from '@angular/material/snack-bar';

@Component({
  selector: 'app-analysis-history',
  templateUrl: './analysis-history.component.html',
  styleUrls: ['./analysis-history.component.css']
})
export class AnalysisHistoryComponent implements OnInit {
  analysisHistory: any[] = [];
  searchName: string = '';
  searchType: string = '';
  searchDate: string = '';
  selectedEntry: any = null;
  editMode: boolean = false;
  searchTypeOther: string = '';
  originalEntry: any = null;

  constructor(
    private smartContractService: SmartContractService, 
    private userService: UserService,
    private snackBar: MatSnackBar
  ) {}

  ngOnInit(): void {
    this.getAnalysisHistory();
  }

  getAnalysisHistory(): void {
    const currentUser = this.userService.currentUserValue;
    if (currentUser && currentUser.id) {
      this.smartContractService.getAnalysisHistory(currentUser.id).subscribe(
        (data: any) => {
          this.analysisHistory = data;
        },
        (error: any) => {
          console.error('Error fetching analysis history:', error);
        }
      );
    } else {
      // Handle user not logged in
    }
  }

  search(): void {
    const currentUser = this.userService.currentUserValue;
    console.log('Current user in search:', currentUser);
      if (currentUser && currentUser.id) {
        console.log(currentUser.id, this.searchName, this.searchType, this.searchDate)
        this.smartContractService.searchAnalysis(currentUser.id, this.searchName, this.searchType, this.searchDate)
      .subscribe({
          next: (data: any) => {
            console.log('Search results:', data); // Log the search results
            this.analysisHistory = data;
          },
          error: (error: any) => {
            console.error('Error searching:', error);
            this.analysisHistory = []; // Clear the table if there's an error
          }
        });
      } else {
          console.warn('User not logged in or ID not available'); // Log if user info is not available
    }
  }

  toggleEdit(): void {
    this.editMode = !this.editMode;
    if (!this.editMode) {
        // When exiting edit mode, refresh the data
        this.selectEntry(this.selectedEntry);
    }
  }

  selectEntry(entry: any): void {
    console.log('Entry selected:', entry); // Log the selected entry
    this.selectedEntry = entry;
    this.editMode = false;
  }


  // Edit smart contract function
  edit(): void {
    this.editMode = true;
    // Make a copy of the selected entry in case the user cancels the edit
    this.originalEntry = { ...this.selectedEntry };
  }
  
  // Save smart contract function
  save(): void {
    if (this.editMode && window.confirm('Are you sure you want to save the changes?')) {
      this.smartContractService.updateContract(this.selectedEntry).subscribe({
        next: (response) => {
          this.snackBar.open('Analysis result saved successfully.', 'Close', {
            duration: 3000,
            horizontalPosition: 'center',
            verticalPosition: 'top',
            panelClass: ['success-snackbar'] // Use a custom class for styling if needed
          });
          this.getAnalysisHistory();
          this.editMode = false;
          this.originalEntry = null;
        },
        error: (error) => {
          this.snackBar.open('Failed to save analysis result. Please try again.', 'Close', {
            duration: 3000,
            horizontalPosition: 'center',
            verticalPosition: 'top',
            panelClass: ['error-snackbar'] // Use a custom class for styling if needed
          });
        }
      });
    }
  }

  // Cancel editing function
  cancel(): void {
    this.editMode = false;
    // Restore the original data
    this.selectedEntry = { ...this.originalEntry };
    this.originalEntry = null;
    // Optionally, refresh the entry to its original state if changes were made
    this.getAnalysisHistory();
  }

  
  // Delete smart contract function
  delete(entryId: number): void {
    if (window.confirm('Are you sure you want to delete this entry?')) {
      this.smartContractService.deleteContract(entryId).subscribe({
        next: () => {
          this.snackBar.open('Entry deleted successfully.', 'Close', {
            duration: 3000,
            horizontalPosition: 'center',
            verticalPosition: 'top',
            panelClass: ['success-snackbar'] // Use a custom class for styling if needed
          });
          this.getAnalysisHistory();
          this.selectedEntry = null; // Clear the selection
        },
        error: (error) => {
          this.snackBar.open('Failed to delete entry. Please try again.', 'Close', {
            duration: 3000,
            horizontalPosition: 'center',
            verticalPosition: 'top',
            panelClass: ['error-snackbar'] // Use a custom class for styling if needed
          });
        }
      });
    }
  }



}
