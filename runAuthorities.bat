@echo off
start cmd /c "java -cp C:\Users\Marta\Documents\NetBeansProjects\FYP\target\FYP-1.0-SNAPSHOT-jar-with-dependencies fyp.UI.PKISetup && pause"
start cmd /c "java -cp C:\Users\Marta\Documents\NetBeansProjects\FYP\target\FYP-1.0-SNAPSHOT-jar-with-dependencies fyp.Authorities.RootCA.RootCA && pause"
timeout 5
start cmd /c "java -cp C:\Users\Marta\Documents\NetBeansProjects\FYP\target\FYP-1.0-SNAPSHOT-jar-with-dependencies fyp.Authorities.CA.CA && pause"
start cmd /c "java -cp C:\Users\Marta\Documents\NetBeansProjects\FYP\target\FYP-1.0-SNAPSHOT-jar-with-dependencies fyp.Authorities.RA.RA && pause"
start cmd /c "java -cp C:\Users\Marta\Documents\NetBeansProjects\FYP\target\FYP-1.0-SNAPSHOT-jar-with-dependencies fyp.Authorities.VA.VA && pause"
timeout 5
start cmd /c "java -cp C:\Users\Marta\Documents\NetBeansProjects\FYP\target\FYP-1.0-SNAPSHOT-jar-with-dependencies fyp.UI.AdminUI && pause"
