import numpy as np
import cv2
from skimage import io
#from matplotlib import pylot as plt


img = cv2.imread('bio_low_contrast.jpg', 1)
#cv2.imshow('my window',img)
lab_img = cv2.cvtColor(img, cv2.COLOR_BGR2LAB)
l, a, b = cv2.split(lab_img)
equ = cv2.equalizeHist(l)
updated_lab_img1 = cv2.merge((equ, a, b))
hist_eq_img = cv2.cvtColor(updated_lab_img1, cv2.COLOR_LAB2BGR)



########### CLAHE ###########
#Apply CLAHE to L channel
clahe = cv2.createCLAHE ( clipLimit = 3.0 , tileGridSize = ( 8,8 ) )
clahe_img = clahe.apply (l)
# plt.hist ( clahe_img.flat , bins = 100 , range = ( 2 , 255 ) )
#Combine the CLAHE enhanced L - channel back with A and B channels updated_lab_img2 = cv2.merge ( ( clahe_img , a , b ) )
updated_lab_img2 = cv2.merge((clahe_img, a, b))

#Convert LAB image back to color ( RGB )
CLAHE_img = cv2.cvtColor ( updated_lab_img2 , cv2.COLOR_LAB2BGR )
cv2.imshow ( " Original image " , img )
cv2.imshow ( " Equalized image " , hist_eq_img )
cv2.imshow ( ' CLAHE Image ' , CLAHE_img )
cv2.waitKey(0)
cv2.destroyAllwindows()
