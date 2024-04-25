import { Component } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { SmartContractService } from '../../smart-contract.service';
import { UserService } from '../../user.service';
import { ChangeDetectorRef } from '@angular/core';
import { OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { MatSnackBar } from '@angular/material/snack-bar';


@Component({
  selector: 'app-smart-contract-card',
  templateUrl: './smart-contract-card.component.html',
  styleUrls: ['./smart-contract-card.component.css']
})
export class SmartContractCardComponent {
  solidityVersion: string = '';
  smartContractCode: string = '';
  analysisResult: any;
  contractName: string = '';
  isLoading: boolean = false;

  constructor(
    private smartContractService: SmartContractService,
    private userService: UserService, // Correctly inject UserService
    private changeDetectorRef: ChangeDetectorRef,
    private router: Router,
    private snackBar: MatSnackBar 
    
  ) {}

  ngOnInit(): void {
    this.checkUserLogin();
  }

  checkUserLogin(): void {
    const currentUser = this.userService.currentUserValue;
    if (!currentUser) {
      console.warn('No user logged in');
      // Redirect to login or handle accordingly
      this.router.navigate(['/login']); // Redirect to login page
    }
  }

  isValidSolidityVersion(version: string): boolean {
    const versionPattern = /^\d+\.\d+\.\d+$/;  // Pattern for "number.number.number" format
    return versionPattern.test(version);
  }

  analyzeSmartContract(): void {
    // Clear previous analysis result
    this.analysisResult = null;
    
    // Only proceed if the Solidity version is valid and smart contract code is not empty
    if (this.isValidSolidityVersion(this.solidityVersion) && this.smartContractCode.trim()) {
      // Set loading to true to show spinner
      this.isLoading = true;
  
      // Perform the analysis
      this.smartContractService.analyzeSmartContract(this.solidityVersion, this.smartContractCode)
        .subscribe({
          next: (response: any) => {
            // Process the response
            this.analysisResult = response;
            this.isLoading = false; // Hide spinner after getting the response
            this.changeDetectorRef.detectChanges(); // Trigger change detection
          },
          error: (error) => {
            console.error('API call failed:', error);
            this.isLoading = false; // Hide spinner on error
            this.snackBar.open('Analysis failed. Please try again.', 'Close', { 
              duration: 3000,
              horizontalPosition: 'center',
              verticalPosition: 'top',
              panelClass: ['my-custom-snackbar'] 
            });
          }
        });
    } else {
      // Show appropriate error message if conditions are not met
      if (!this.isValidSolidityVersion(this.solidityVersion)) {
        this.snackBar.open('Solidity version format is incorrect. Use format: X.Y.Z (e.g., 0.8.4)', 'Close', {
          duration: 3000,
          verticalPosition: 'top',
          horizontalPosition: 'center',
          panelClass: ['centered-snack-bar']
        });
      } else if (!this.smartContractCode.trim()) {
        this.snackBar.open('Please enter the smart contract code.', 'Close', {
          duration: 3000,
          verticalPosition: 'top',
          horizontalPosition: 'center',
          panelClass: ['centered-snack-bar']
        });
      }
    }
  }
  

  saveSmartContract(): void {
    // Retrieve the current user from UserService
    const currentUser = this.userService.currentUserValue;
    console.log('Current user:', currentUser);

    if (!currentUser || !currentUser.id) {
      console.error('User not logged in or user ID not available');
      return;
    }

    if (!this.contractName) {
      // You may want to alert the user or handle this situation appropriately
      console.error('Contract name is required');
      return;
    }

    // Pass the current user's ID when calling saveContract
    const confirmation = window.confirm('Are you sure you want to save this analysis result?');
    if (confirmation) {
      this.smartContractService.saveContract(
        this.contractName, 
        this.solidityVersion, 
        this.smartContractCode,
        currentUser.id, // User ID
        this.analysisResult.Vulnerabilities // Array of vulnerabilities
      )
      .subscribe({
        next: (response) => {
          this.snackBar.open('Analysis result saved successfully.', 'Close', {
            duration: 3000,
            horizontalPosition: 'center',
            verticalPosition: 'top',
            panelClass: ['my-custom-snackbar']  // Optional: you can define this class in your styles to customize the snackbar
          });

          this.analysisResult = response;
          this.changeDetectorRef.detectChanges(); // Manually trigger change detection
        },
        error: (error) => {
          console.error('API call failed:', error);
          this.snackBar.open('Failed to save analysis result. Please try again.', 'Close', { 
            duration: 3000,
            horizontalPosition: 'center',
            verticalPosition: 'top',
            panelClass: ['my-custom-snackbar'] 
          });
        }
      });
    }
  }
}
