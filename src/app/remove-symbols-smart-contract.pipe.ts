import { Pipe, PipeTransform } from '@angular/core';

@Pipe({
  name: 'removeSymbolsSmartContract'
})
export class RemoveSymbolsSmartContractPipe implements PipeTransform {

  transform(value: string): string {
    if (!value) return '';
    // Regular expression to match *, **, and -
    // Add or remove symbols from the regex as needed
      return value.replace(/[\*\-\#]/g, '');
    
  }

}
