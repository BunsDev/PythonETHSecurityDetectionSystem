import { ComponentFixture, TestBed } from '@angular/core/testing';

import { SmartContractCardComponent } from './smart-contract-card.component';

describe('SmartContractCardComponent', () => {
  let component: SmartContractCardComponent;
  let fixture: ComponentFixture<SmartContractCardComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [SmartContractCardComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(SmartContractCardComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
