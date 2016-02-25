from __future__ import nested_scopes, generators, division, absolute_import, with_statement, print_function, unicode_literals
import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, Boolean, Float, Date, Table, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from sqlalchemy import create_engine
 
Base = declarative_base()

# Create Properties Table
class Properties(Base):
  __tablename__ = 'properties'

  pID = Column(Integer, primary_key=True)
  userEmail = Column(String(100))
  pCity = Column(String(50))
  pState = Column(String(2))
  pAcres = Column(Integer)
  pTitle = Column(String(100))
  pDescription = Column(String(2000))
  pPrice = Column(Integer)
  pRentType = Column(String(10)) # Private, Public, Guided, SemiGuided, Lease

  # Generate data for API
  @property
  def serialize(self):
    return {
      'id' : self.pID,
			'title' : self.pTitle,
      'city' : self.pCity,
      'state' : self.pState,
      'acres' : self.pAcres,
      'description' : self.pDescription,
			'price' : self.pPrice,
			'rentType' : self.pRentType
    }


engine = create_engine('sqlite:///database.db')
 

Base.metadata.create_all(engine)
